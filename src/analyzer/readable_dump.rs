use eyre::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use alloy_rlp::Decodable;
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use serde::{Deserialize, Serialize};
use crate::analyzer::mdbx::MdbxAnalyzer;
use crate::analyzer::static_file::StaticFileAnalyzer;

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

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadableBlock {
    pub format: String,
    pub general_gas_limit: u64,
    pub shared_gas_limit: u64,
    pub timestamp_millis_part: u64,
    pub header: ReadableHeader,
    pub transactions: Vec<ReadableTransaction>,
    pub ommers: Vec<ReadableHeader>,
    pub raw_size_bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadableHeader {
    pub parent_hash: String,
    pub ommers_hash: String,
    pub beneficiary: String,
    pub state_root: String,
    pub transactions_root: String,
    pub receipts_root: String,
    pub logs_bloom: String,
    pub difficulty: String,
    pub number: u64,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadableTransaction {
    pub tx_type: String,
    pub raw_data: String, // For now, keep as hex
}

pub fn dump_readable_files(datadir: &Path, output: &Path) -> Result<()> {
    // Dump MDBX database (execution state)
    dump_mdbx_readable(datadir, output)?;

    // Dump Consensus data
    dump_consensus_readable(datadir, output)?;

    // Dump Static files (historical data)
    dump_static_files_readable(datadir, output)?;

    println!();
    println!("Parsing complete. Results saved to: {}", output.display());

    Ok(())
}

fn dump_consensus_readable(datadir: &Path, output: &Path) -> Result<()> {
    let consensus_path = datadir.join("consensus");

    // Get absolute paths for abbreviation
    let datadir_abs = datadir.canonicalize().unwrap_or(datadir.to_path_buf());
    let output_abs = output.canonicalize().unwrap_or(output.to_path_buf());

    println!("Consensus Data:");

    // Parse finalized blocks using ordinal file
    let finalized_ordinal_path = consensus_path.join("engine-finalized_blocks-ordinal/0000000000000000");
    let finalized_value_path = consensus_path.join("engine-finalized_blocks-freezer-value/0000000000000000");

    if finalized_ordinal_path.exists() && finalized_value_path.exists() {
        match parse_freezer_blocks_with_ordinal(&finalized_ordinal_path, &finalized_value_path) {
            Ok(blocks) => {
                let out_path = output.join("readable_finalized_blocks.json");
                let json = serde_json::to_string_pretty(&blocks)?;
                fs::write(&out_path, json)?;

                let out_path_abs = out_path.canonicalize().unwrap_or(out_path.clone());
                let finalized_ordinal_abs = finalized_ordinal_path.canonicalize().unwrap_or(finalized_ordinal_path.to_path_buf());
                let finalized_value_abs = finalized_value_path.canonicalize().unwrap_or(finalized_value_path.to_path_buf());

                println!("parsed {} finalized blocks", blocks.len());
                println!("- out: {}", abbreviate_path(&out_path_abs, &datadir_abs, &output_abs));
                println!("- src: {}", abbreviate_path(&finalized_ordinal_abs, &datadir_abs, &output_abs));
                println!("- src: {}", abbreviate_path(&finalized_value_abs, &datadir_abs, &output_abs));
            }
            Err(e) => {
                println!("✗ Finalized blocks failed: {:?}", e);
            }
        }
    } else if finalized_value_path.exists() {
        match parse_cwic_blocks(&finalized_value_path) {
            Ok(blocks) => {
                let out_path = output.join("readable_finalized_blocks.json");
                let json = serde_json::to_string_pretty(&blocks)?;
                fs::write(&out_path, json)?;

                let out_path_abs = out_path.canonicalize().unwrap_or(out_path.clone());
                let finalized_value_abs = finalized_value_path.canonicalize().unwrap_or(finalized_value_path.to_path_buf());

                println!("parsed {} finalized blocks", blocks.len());
                println!("- out: {}", abbreviate_path(&out_path_abs, &datadir_abs, &output_abs));
                println!("- src: {}", abbreviate_path(&finalized_value_abs, &datadir_abs, &output_abs));
            }
            Err(_e) => {
                // Silent failure
            }
        }
    }

    // Parse notarized blocks (cache format)
    let notarized_key_path = consensus_path.join("engine-cache-cache-0-notarized-key/0000000000000000");
    let notarized_value_path = consensus_path.join("engine-cache-cache-0-notarized-value/0000000000000000");

    if notarized_key_path.exists() && notarized_value_path.exists() {
        match parse_cache_blocks(&notarized_key_path, &notarized_value_path) {
            Ok(blocks) => {
                let out_path = output.join("readable_notarized_blocks.json");
                let json = serde_json::to_string_pretty(&blocks)?;
                fs::write(&out_path, json)?;

                let out_path_abs = out_path.canonicalize().unwrap_or(out_path.clone());
                let notarized_key_abs = notarized_key_path.canonicalize().unwrap_or(notarized_key_path.to_path_buf());
                let notarized_value_abs = notarized_value_path.canonicalize().unwrap_or(notarized_value_path.to_path_buf());

                println!("parsed {} notarized blocks", blocks.len());
                println!("- out: {}", abbreviate_path(&out_path_abs, &datadir_abs, &output_abs));
                println!("- src: {}", abbreviate_path(&notarized_key_abs, &datadir_abs, &output_abs));
                println!("- src: {}", abbreviate_path(&notarized_value_abs, &datadir_abs, &output_abs));
            }
            Err(_e) => {
                // Silent failure
            }
        }
    }

    // Parse verified blocks (cache format)
    let verified_key_path = consensus_path.join("engine-cache-cache-0-verified-key/0000000000000000");
    let verified_value_path = consensus_path.join("engine-cache-cache-0-verified-value/0000000000000000");

    if verified_key_path.exists() && verified_value_path.exists() {
        match parse_cache_blocks(&verified_key_path, &verified_value_path) {
            Ok(blocks) => {
                let out_path = output.join("readable_verified_blocks.json");
                let json = serde_json::to_string_pretty(&blocks)?;
                fs::write(&out_path, json)?;

                let out_path_abs = out_path.canonicalize().unwrap_or(out_path.clone());
                let verified_key_abs = verified_key_path.canonicalize().unwrap_or(verified_key_path.to_path_buf());
                let verified_value_abs = verified_value_path.canonicalize().unwrap_or(verified_value_path.to_path_buf());

                println!("parsed {} verified blocks", blocks.len());
                println!("- out: {}", abbreviate_path(&out_path_abs, &datadir_abs, &output_abs));
                println!("- src: {}", abbreviate_path(&verified_key_abs, &datadir_abs, &output_abs));
                println!("- src: {}", abbreviate_path(&verified_value_abs, &datadir_abs, &output_abs));
            }
            Err(_e) => {
                // Silent failure
            }
        }
    }

    // Parse finalization certificates
    let finalizations_ordinal_path = consensus_path.join("engine-finalizations-by-height-ordinal/0000000000000000");
    let finalizations_value_path = consensus_path.join("engine-finalizations-by-height-freezer-value/0000000000000000");

    if finalizations_ordinal_path.exists() && finalizations_value_path.exists() {
        match parse_finalization_certificates(&finalizations_ordinal_path, &finalizations_value_path) {
            Ok(certs) => {
                let out_path = output.join("readable_finalization_certificates.json");
                let json = serde_json::to_string_pretty(&certs)?;
                fs::write(&out_path, json)?;

                let out_path_abs = out_path.canonicalize().unwrap_or(out_path.clone());
                let finalizations_ordinal_abs = finalizations_ordinal_path.canonicalize().unwrap_or(finalizations_ordinal_path.to_path_buf());
                let finalizations_value_abs = finalizations_value_path.canonicalize().unwrap_or(finalizations_value_path.to_path_buf());

                println!("parsed {} finalization certificates", certs.len());
                println!("- out: {}", abbreviate_path(&out_path_abs, &datadir_abs, &output_abs));
                println!("- src: {}", abbreviate_path(&finalizations_ordinal_abs, &datadir_abs, &output_abs));
                println!("- src: {}", abbreviate_path(&finalizations_value_abs, &datadir_abs, &output_abs));
            }
            Err(_e) => {
                // Silent failure
            }
        }
    }

    // Parse DKG events
    let dkg_events_path = consensus_path.join("engine_dkg_manager_events/0000000000000000");
    if dkg_events_path.exists() {
        match parse_cwic_data(&dkg_events_path) {
            Ok(data) => {
                let out_path = output.join("readable_dkg_events.json");
                fs::write(&out_path, data)?;

                let out_path_abs = out_path.canonicalize().unwrap_or(out_path.clone());
                let dkg_events_abs = dkg_events_path.canonicalize().unwrap_or(dkg_events_path.to_path_buf());

                println!("parsed DKG events");
                println!("- out: {}", abbreviate_path(&out_path_abs, &datadir_abs, &output_abs));
                println!("- src: {}", abbreviate_path(&dkg_events_abs, &datadir_abs, &output_abs));
            }
            Err(_e) => {
                // Silent failure
            }
        }
    }

    println!();
    Ok(())
}

fn parse_cwic_blocks(file_path: &Path) -> Result<Vec<ReadableBlock>> {
    let data = fs::read(file_path)?;

    if data.len() < 8 {
        eyre::bail!("File too small for CWIC format");
    }

    // Check CWIC magic
    if &data[0..4] != b"CWIC" {
        eyre::bail!("Not a CWIC file (magic mismatch)");
    }

    println!("    CWIC magic verified");

    // Skip CWIC header (8 bytes)
    let payload_raw = &data[8..];

    // Check if data is compressed (finalized blocks use zstd compression)
    let payload: Vec<u8>;
    let payload_ref: &[u8];

    // Check if data is zstd-compressed (finalized blocks)
    if payload_raw.len() >= 4 && payload_raw[0..4] == [0x28, 0xB5, 0x2F, 0xFD] {
        // zstd magic detected
        println!("    Detected zstd compression");

        // Try ruzstd (pure Rust implementation, more forgiving)
        use std::io::Read;
        match ruzstd::StreamingDecoder::new(payload_raw) {
            Ok(mut decoder) => {
                let mut decompressed = Vec::new();
                match decoder.read_to_end(&mut decompressed) {
                    Ok(_) => {
                        println!("    Decompressed {} -> {} bytes", payload_raw.len(), decompressed.len());
                        payload = decompressed;
                        payload_ref = &payload;
                    }
                    Err(e) => {
                        println!("    Warning: ruzstd decompression failed: {}", e);
                        println!("    Treating as uncompressed data");
                        payload_ref = payload_raw;
                    }
                }
            }
            Err(e) => {
                println!("    Warning: ruzstd decoder creation failed: {}", e);
                println!("    Treating as uncompressed data");
                payload_ref = payload_raw;
            }
        }
    } else {
        payload_ref = payload_raw;
    }

    // Try to find valid RLP start by testing different offsets
    // For finalized blocks with suspected compression/framing, try 0 first
    let possible_offsets = [0, 12, 16, 20, 4, 8]; // Common metadata sizes
    let mut rlp_start = 0;
    let mut found = false;

    for &offset in &possible_offsets {
        if offset >= payload_ref.len() {
            continue;
        }

        let test_data = &payload_ref[offset..];
        if test_data.is_empty() {
            continue;
        }

        // Check if this looks like a valid RLP list start
        if test_data[0] == 0xf9 && test_data.len() >= 3 {
            // 0xf9 = long list, next 2 bytes are length
            println!("    Skipping {} bytes of metadata before RLP", offset);
            rlp_start = offset;
            found = true;
            break;
        } else if test_data[0] >= 0xc0 && test_data[0] <= 0xf7 && offset == 0 {
            // Short list/string at the start
            println!("    RLP data starts immediately after CWIC header");
            rlp_start = 0;
            found = true;
            break;
        }
    }

    if !found {
        println!("    Warning: Could not find clear RLP start marker, trying offset 0");
    }

    let rlp_data = &payload_ref[rlp_start..];

    // Try to parse as RLP list
    let mut blocks = Vec::new();

    // The data might be a single RLP-encoded block or multiple
    let mut offset = 0;
    let mut block_count = 0;

    while offset < rlp_data.len() {
        match parse_rlp_block(&rlp_data[offset..]) {
            Ok((block, consumed)) => {
                blocks.push(block);
                offset += consumed;
                block_count += 1;
                println!("    Parsed block #{}", block_count);

                // Safety check: if we consumed 0 bytes, break to avoid infinite loop
                if consumed == 0 {
                    break;
                }
            }
            Err(e) => {
                if block_count == 0 {
                    // If we couldn't parse even the first block, it's an error
                    return Err(e);
                } else {
                    // We parsed some blocks successfully, stop here
                    println!("    Stopped parsing after {} block(s) (remaining data may not be blocks)", block_count);
                    break;
                }
            }
        }

        // Safety limit: don't try to parse more than 1000 blocks
        if block_count >= 1000 {
            println!("    Reached safety limit of 1000 blocks");
            break;
        }
    }

    Ok(blocks)
}

fn parse_rlp_block(data: &[u8]) -> Result<(ReadableBlock, usize)> {
    // RLP-decode the block
    // Expected structure: [header, transactions, ommers]

    if data.len() < 10 {
        eyre::bail!("Data too small to be a valid block (need at least 10 bytes, got {})", data.len());
    }

    // Decode the RLP header
    let header = alloy_rlp::Header::decode(&mut &data[..]).context("Failed to decode RLP header")?;

    if !header.list {
        eyre::bail!("Expected RLP list for block");
    }

    let total_consumed = header.payload_length + header.length();

    println!("      RLP header: list={}, payload_length={}, header_length={}, total={}",
             header.list, header.payload_length, header.length(), total_consumed);

    if total_consumed > data.len() {
        eyre::bail!("Not enough data for block (need {}, have {})", total_consumed, data.len());
    }

    // The data contains the first block's payload (and possibly more blocks after)
    // We need to limit cursor to just the first block's payload
    let block_payload = &data[header.length()..total_consumed];
    let mut cursor = block_payload;

    // Now decode the inner list (the actual block)
    let inner_header = alloy_rlp::Header::decode(&mut &cursor[..]).context("Failed to decode inner list header")?;

    if !inner_header.list {
        eyre::bail!("Expected RLP list for inner block");
    }

    println!("      Inner block list: {} bytes payload", inner_header.payload_length);
    println!("      Block payload slice: {} bytes", block_payload.len());

    // Skip the inner list header to get to the Tempo block fields
    cursor = &cursor[inner_header.length()..];

    // Parse Tempo block structure: [general_gas_limit, shared_gas_limit, timestamp_millis_part, inner_header, txs, ommers]
    println!("      Parsing Tempo block fields...");

    // Field 1: general_gas_limit
    let general_gas_limit = u64::decode(&mut cursor).context("Failed to decode general_gas_limit")?;
    println!("        general_gas_limit: {}", general_gas_limit);

    // Field 2: shared_gas_limit
    let shared_gas_limit = u64::decode(&mut cursor).context("Failed to decode shared_gas_limit")?;
    println!("        shared_gas_limit: {}", shared_gas_limit);

    // Field 3: timestamp_millis_part
    let timestamp_millis_part = u64::decode(&mut cursor).context("Failed to decode timestamp_millis_part")?;
    println!("        timestamp_millis_part: {}", timestamp_millis_part);

    // Debug: show cursor position before parsing Ethereum header

    // Field 4: inner Ethereum header (as nested list)
    let header = parse_ethereum_header(&mut cursor).context("Failed to parse inner Ethereum header")?;
    println!("        Parsed Ethereum header for block #{}", header.number);

    // Field 5: transactions list
    let transactions = Vec::new();
    if cursor.len() > 0 {
        if let Ok(tx_list_header) = alloy_rlp::Header::decode(&mut cursor) {
            if tx_list_header.list {
                println!("        Found {} bytes of transaction data", tx_list_header.payload_length);
                // Skip transaction parsing for now
                cursor = &cursor[tx_list_header.payload_length..];
            }
        }
    }

    // Field 6: ommers list (usually empty)
    let ommers = Vec::new();
    if cursor.len() > 0 {
        if let Ok(ommer_list_header) = alloy_rlp::Header::decode(&mut cursor) {
            if ommer_list_header.list {
                println!("        Found {} bytes of ommer data", ommer_list_header.payload_length);
            }
        }
    }

    let block = ReadableBlock {
        format: "Tempo consensus block".to_string(),
        general_gas_limit,
        shared_gas_limit,
        timestamp_millis_part,
        header,
        transactions,
        ommers,
        raw_size_bytes: total_consumed,
    };

    println!("      Successfully parsed Tempo block ({} bytes)", total_consumed);

    Ok((block, total_consumed))
}

fn parse_ethereum_header(cursor: &mut &[u8]) -> Result<ReadableHeader> {
    // The inner Ethereum header is encoded as a nested RLP list
    let list_header = alloy_rlp::Header::decode(&mut &cursor[..]).context("Failed to decode header list")?;

    if !list_header.list {
        eyre::bail!("Expected RLP list for Ethereum header");
    }

    // Manually advance cursor past the list header
    *cursor = &cursor[list_header.length()..];

    // Standard Ethereum header fields (15 required + up to 6 optional)
    let parent_hash = B256::decode(cursor).context("Failed to decode parent_hash")?;
    let ommers_hash = B256::decode(cursor).context("Failed to decode ommers_hash")?;
    let beneficiary = Address::decode(cursor).context("Failed to decode beneficiary")?;

    let state_root = B256::decode(cursor).context("Failed to decode state_root")?;
    let transactions_root = B256::decode(cursor).context("Failed to decode transactions_root")?;
    let receipts_root = B256::decode(cursor).context("Failed to decode receipts_root")?;
    let logs_bloom = Bloom::decode(cursor).context("Failed to decode logs_bloom")?;
    let difficulty = U256::decode(cursor).context("Failed to decode difficulty")?;

    // Note: alloy_consensus encodes number, gas_limit, gas_used as U256
    let number = U256::decode(cursor).context("Failed to decode number")?.to::<u64>();
    let gas_limit = U256::decode(cursor).context("Failed to decode gas_limit")?.to::<u64>();
    let gas_used = U256::decode(cursor).context("Failed to decode gas_used")?.to::<u64>();

    let timestamp = u64::decode(cursor).context("Failed to decode timestamp")?;
    let extra_data = Bytes::decode(cursor).context("Failed to decode extra_data")?;
    let mix_hash = B256::decode(cursor).context("Failed to decode mix_hash")?;
    let nonce_b64 = B64::decode(cursor).context("Failed to decode nonce")?;
    let nonce = u64::from_be_bytes(nonce_b64.0);

    // Optional EIP-1559 fields (base_fee_per_gas is encoded as U256)
    let base_fee_per_gas = if cursor.len() > 0 {
        U256::decode(cursor).ok().map(|v| v.to::<u64>())
    } else {
        None
    };

    // Optional EIP-4895 (withdrawals)
    let withdrawals_root = if cursor.len() > 0 {
        B256::decode(cursor).ok().map(|h| format!("0x{}", hex::encode(h.as_slice())))
    } else {
        None
    };

    // Optional EIP-4844 (blob) - also encoded as U256
    let blob_gas_used = if cursor.len() > 0 {
        U256::decode(cursor).ok().map(|v| v.to::<u64>())
    } else {
        None
    };

    let excess_blob_gas = if cursor.len() > 0 {
        U256::decode(cursor).ok().map(|v| v.to::<u64>())
    } else {
        None
    };

    // Optional EIP-4788 (beacon root)
    let parent_beacon_block_root = if cursor.len() > 0 {
        B256::decode(cursor).ok().map(|h| format!("0x{}", hex::encode(h.as_slice())))
    } else {
        None
    };

    // Optional EIP-7685 (requests hash)
    let requests_hash = if cursor.len() > 0 {
        B256::decode(cursor).ok().map(|h| format!("0x{}", hex::encode(h.as_slice())))
    } else {
        None
    };

    Ok(ReadableHeader {
        parent_hash: format!("0x{}", hex::encode(parent_hash.as_slice())),
        ommers_hash: format!("0x{}", hex::encode(ommers_hash.as_slice())),
        beneficiary: format!("0x{}", hex::encode(beneficiary.as_slice())),
        state_root: format!("0x{}", hex::encode(state_root.as_slice())),
        transactions_root: format!("0x{}", hex::encode(transactions_root.as_slice())),
        receipts_root: format!("0x{}", hex::encode(receipts_root.as_slice())),
        logs_bloom: format!("0x{}", hex::encode(logs_bloom.as_slice())),
        difficulty: difficulty.to_string(),
        number,
        gas_limit,
        gas_used,
        timestamp,
        extra_data: format!("0x{}", hex::encode(&extra_data)),
        mix_hash: format!("0x{}", hex::encode(mix_hash.as_slice())),
        nonce,
        base_fee_per_gas,
        withdrawals_root,
        blob_gas_used,
        excess_blob_gas,
        parent_beacon_block_root,
        requests_hash,
    })
}

#[allow(dead_code)]
fn estimate_list_items(data: &[u8]) -> usize {
    // Rough estimate by counting RLP list/string headers
    let mut count = 0;
    let mut offset = 0;

    while offset < data.len() {
        if let Ok(header) = alloy_rlp::Header::decode(&mut &data[offset..]) {
            count += 1;
            offset += header.length() + header.payload_length;
        } else {
            break;
        }

        if count > 10000 {
            break; // Safety limit
        }
    }

    count
}

// Parse finalization certificates using ordinal index
fn parse_finalization_certificates(ordinal_path: &Path, value_path: &Path) -> Result<Vec<serde_json::Value>> {
    use std::io::Read;

    // Read ordinal file to get offsets
    let ordinal_data = fs::read(ordinal_path)?;
    if ordinal_data.len() < 8 || &ordinal_data[0..4] != b"CWIC" {
        eyre::bail!("Invalid ordinal file");
    }

    let mut offset = 48;  // Skip CWIC header
    let mut entries = Vec::new();

    while offset + 144 <= ordinal_data.len() {
        let entry_data = &ordinal_data[offset..offset + 144];
        if entry_data[0..16].iter().all(|&b| b == 0) {
            break;
        }

        let value_offset = u16::from_be_bytes([entry_data[22], entry_data[23]]) as u64;
        let value_size = u16::from_be_bytes([entry_data[26], entry_data[27]]) as u64;

        entries.push((value_offset, value_size));
        offset += 144;
    }

    // Read and decompress value file
    let value_data = fs::read(value_path)?;
    if value_data.len() < 8 || &value_data[0..4] != b"CWIC" {
        eyre::bail!("Invalid value file");
    }

    let compressed_data = &value_data[8..];
    let mut certificates = Vec::new();

    for (idx, (cert_offset, cert_size)) in entries.iter().enumerate() {
        let start = *cert_offset as usize;
        let size = *cert_size as usize;

        if start + size > compressed_data.len() {
            continue;
        }

        let compressed_frame = &compressed_data[start..start + size];

        // Check zstd magic
        if compressed_frame.len() < 4 || compressed_frame[0..4] != [0x28, 0xB5, 0x2F, 0xFD] {
            continue;
        }

        // Decompress
        if let Ok(mut decoder) = ruzstd::StreamingDecoder::new(compressed_frame) {
            let mut decompressed = Vec::new();
            if decoder.read_to_end(&mut decompressed).is_ok() {
                // Parse certificate structure
                let cert = parse_finalization_certificate_data(&decompressed, idx);
                certificates.push(cert);
            }
        }
    }

    Ok(certificates)
}

// Decode a Protocol Buffers varint (used by Commonware codec for u64)
// Returns (decoded_value, bytes_consumed)
fn decode_varint(data: &[u8]) -> Result<(u64, usize), String> {
    let mut result: u64 = 0;
    let mut shift = 0;

    for (i, &byte) in data.iter().enumerate() {
        if i > 9 {
            // u64 can't take more than 10 bytes in varint encoding
            return Err("Varint too long".to_string());
        }

        // Extract the 7 data bits
        let value_bits = (byte & 0x7F) as u64;
        result |= value_bits << shift;

        // Check if this is the last byte (continuation bit not set)
        if (byte & 0x80) == 0 {
            return Ok((result, i + 1));
        }

        shift += 7;
    }

    Err("Varint incomplete".to_string())
}

// Parse individual finalization certificate from decompressed data
fn parse_finalization_certificate_data(data: &[u8], index: usize) -> serde_json::Value {
    // Finalization certificate structure (commonware codec format):
    // 1. Round: epoch (varint u64) + view (varint u64)
    // 2. Proposal payload (Digest): 32 bytes fixed
    // 3. Certificate (BLS12-381 threshold signature): remaining bytes
    //    - 48 bytes: G1 point (compressed signature)
    //    - Remaining: Bitmap/participation metadata

    if data.len() < 3 {
        return serde_json::json!({
            "certificate_index": index,
            "size_bytes": data.len(),
            "data_hex": hex::encode(data),
            "error": "Certificate too small (need at least 3 bytes)"
        });
    }

    // Parse epoch (varint)
    let (epoch, epoch_size) = match decode_varint(data) {
        Ok(v) => v,
        Err(e) => return serde_json::json!({
            "certificate_index": index,
            "size_bytes": data.len(),
            "data_hex": hex::encode(data),
            "error": format!("Failed to decode epoch varint: {}", e)
        }),
    };

    // Parse view (varint)
    let (view, view_size) = match decode_varint(&data[epoch_size..]) {
        Ok(v) => v,
        Err(e) => return serde_json::json!({
            "certificate_index": index,
            "size_bytes": data.len(),
            "data_hex": hex::encode(data),
            "error": format!("Failed to decode view varint: {}", e)
        }),
    };

    let digest_start = epoch_size + view_size;
    let digest_end = digest_start + 32;

    if data.len() < digest_end {
        return serde_json::json!({
            "certificate_index": index,
            "size_bytes": data.len(),
            "epoch": epoch,
            "view": view,
            "data_hex": hex::encode(data),
            "error": format!("Certificate too small (need {} bytes for digest)", digest_end)
        });
    }

    // Parse Digest (32 bytes fixed)
    let block_digest = hex::encode(&data[digest_start..digest_end]);

    // Certificate data (remaining bytes)
    let certificate_data = &data[digest_end..];
    let certificate_size = certificate_data.len();
    let certificate_preview = if certificate_size > 0 {
        hex::encode(&certificate_data[..certificate_size.min(64)])
    } else {
        "".to_string()
    };

    serde_json::json!({
        "certificate_index": index,
        "epoch": epoch,
        "view": view,
        "block_digest": format!("0x{}", block_digest),
        "certificate_size_bytes": certificate_size,
        "certificate_preview_hex": certificate_preview,
        "total_size_bytes": data.len(),
        "round_size_bytes": digest_start,
        "format": "Finalization<BLS12-381, Digest>",
        "description": "Finalization certificate with 2f+1 validator threshold signatures"
    })
}

fn parse_cwic_data(file_path: &Path) -> Result<String> {
    let data = fs::read(file_path)?;

    if data.len() < 8 || &data[0..4] != b"CWIC" {
        eyre::bail!("Not a CWIC file");
    }

    // Skip CWIC header
    let mut payload = &data[8..];
    let mut messages = Vec::new();
    let mut message_index = 0;

    // Parse DKG messages
    while !payload.is_empty() && message_index < 10000 {
        // Try to parse length prefix (varint)
        let (msg_length, length_size) = match decode_varint(payload) {
            Ok(v) => v,
            Err(e) => {
                // If we can't decode varint, we're done or at unparseable data
                messages.push(serde_json::json!({
                    "message_index": message_index,
                    "error": format!("Failed to decode message length: {}", e),
                    "remaining_bytes": payload.len(),
                    "remaining_hex_preview": hex::encode(&payload[..payload.len().min(64)])
                }));
                break;
            }
        };

        payload = &payload[length_size..];

        if payload.len() < msg_length as usize {
            messages.push(serde_json::json!({
                "message_index": message_index,
                "error": format!("Message truncated: expected {} bytes, got {}", msg_length, payload.len()),
                "remaining_hex": hex::encode(payload)
            }));
            break;
        }

        let msg_data = &payload[..msg_length as usize];
        payload = &payload[msg_length as usize..];

        // Parse message tag (1 byte)
        if msg_data.is_empty() {
            messages.push(serde_json::json!({
                "message_index": message_index,
                "error": "Empty message data"
            }));
            message_index += 1;
            continue;
        }

        let tag = msg_data[0];
        let msg_content = &msg_data[1..];

        let message_info = match tag {
            0 => {
                // Dealer message: dealer (PublicKey, 32 bytes) + DealerPubMsg + DealerPrivMsg
                let dealer_pubkey = if msg_content.len() >= 32 {
                    hex::encode(&msg_content[0..32])
                } else {
                    "insufficient_data".to_string()
                };

                serde_json::json!({
                    "message_index": message_index,
                    "type": "Dealing",
                    "tag": 0,
                    "size_bytes": msg_data.len(),
                    "dealer_pubkey": format!("0x{}", dealer_pubkey),
                    "content_size_bytes": msg_content.len(),
                    "data_hex_preview": hex::encode(&msg_content[..msg_content.len().min(128)]),
                    "description": "Dealing event: dealer + DealerPubMsg + DealerPrivMsg"
                })
            }
            1 => {
                // Ack message: player (PublicKey, 32 bytes) + PlayerAck
                let player_pubkey = if msg_content.len() >= 32 {
                    hex::encode(&msg_content[0..32])
                } else {
                    "insufficient_data".to_string()
                };

                serde_json::json!({
                    "message_index": message_index,
                    "type": "Ack",
                    "tag": 1,
                    "size_bytes": msg_data.len(),
                    "player_pubkey": format!("0x{}", player_pubkey),
                    "content_size_bytes": msg_content.len(),
                    "data_hex_preview": hex::encode(&msg_content[..msg_content.len().min(128)]),
                    "description": "Ack event: player + PlayerAck"
                })
            }
            2 => {
                // Log message: dealer (PublicKey, 32 bytes) + DealerLog
                let dealer_pubkey = if msg_content.len() >= 32 {
                    hex::encode(&msg_content[0..32])
                } else {
                    "insufficient_data".to_string()
                };

                serde_json::json!({
                    "message_index": message_index,
                    "type": "Log",
                    "tag": 2,
                    "size_bytes": msg_data.len(),
                    "dealer_pubkey": format!("0x{}", dealer_pubkey),
                    "content_size_bytes": msg_content.len(),
                    "data_hex_preview": hex::encode(&msg_content[..msg_content.len().min(128)]),
                    "description": "Log event: dealer + DealerLog (from finalized block)"
                })
            }
            3 => {
                // Finalized event: digest (32 bytes) + parent (32 bytes) + height (varint)
                if msg_content.len() < 64 {
                    serde_json::json!({
                        "message_index": message_index,
                        "type": "Finalized",
                        "tag": 3,
                        "size_bytes": msg_data.len(),
                        "error": format!("Insufficient data for Finalized event: expected >= 64 bytes, got {}", msg_content.len()),
                        "data_hex": hex::encode(msg_content)
                    })
                } else {
                    let digest = hex::encode(&msg_content[0..32]);
                    let parent = hex::encode(&msg_content[32..64]);

                    // Parse height (varint)
                    let height_result = decode_varint(&msg_content[64..]);

                    if let Err(e) = height_result {
                        serde_json::json!({
                            "message_index": message_index,
                            "type": "Finalized",
                            "tag": 3,
                            "size_bytes": msg_data.len(),
                            "digest": format!("0x{}", digest),
                            "parent": format!("0x{}", parent),
                            "error": format!("Failed to decode height varint: {}", e),
                            "remaining_hex": hex::encode(&msg_content[64..])
                        })
                    } else {
                        let (height, height_size) = height_result.unwrap();

                        serde_json::json!({
                            "message_index": message_index,
                            "type": "Finalized",
                            "tag": 3,
                            "size_bytes": msg_data.len(),
                            "digest": format!("0x{}", digest),
                            "parent": format!("0x{}", parent),
                            "height": height,
                            "height_size_bytes": height_size,
                            "total_size_bytes": 64 + height_size,
                            "description": "Finalized event: information about finalized block observed by DKG manager"
                        })
                    }
                }
            }
            other => {
                serde_json::json!({
                    "message_index": message_index,
                    "type": "Unknown",
                    "tag": other,
                    "size_bytes": msg_data.len(),
                    "error": format!("Unknown message tag: {}", other),
                    "data_hex_preview": hex::encode(&msg_content[..msg_content.len().min(128)])
                })
            }
        };

        messages.push(message_info);
        message_index += 1;
    }

    let analysis = serde_json::json!({
        "format": "CWIC - DKG Events",
        "total_size": data.len(),
        "payload_size": data.len() - 8,
        "message_count": messages.len(),
        "messages": messages
    });

    Ok(serde_json::to_string_pretty(&analysis)?)
}

#[allow(dead_code)]
fn parse_rlp_value(data: &mut &[u8]) -> Result<serde_json::Value> {
    if data.is_empty() {
        return Ok(serde_json::json!(null));
    }

    let header = alloy_rlp::Header::decode(data)?;

    if header.list {
        // Parse list
        let payload_end = data.len().min(header.payload_length);
        let mut list_data = &data[..payload_end];
        *data = &data[payload_end..];

        let mut items = Vec::new();
        let mut item_count = 0;

        while !list_data.is_empty() && item_count < 1000 {
            match parse_rlp_value(&mut list_data) {
                Ok(value) => items.push(value),
                Err(_) => break,
            }
            item_count += 1;
        }

        Ok(serde_json::json!({
            "type": "list",
            "length": items.len(),
            "items": items
        }))
    } else {
        // Parse byte string
        let payload_end = data.len().min(header.payload_length);
        let bytes = &data[..payload_end];
        *data = &data[payload_end..];

        // Try to interpret the data
        let hex_str = hex::encode(bytes);

        let interpretation = if bytes.len() == 32 {
            // Likely a hash
            serde_json::json!({
                "type": "hash",
                "hex": format!("0x{}", hex_str),
                "bytes": bytes.len()
            })
        } else if bytes.len() == 20 {
            // Likely an address
            serde_json::json!({
                "type": "address",
                "hex": format!("0x{}", hex_str),
                "bytes": bytes.len()
            })
        } else if bytes.len() <= 8 {
            // Try to decode as integer
            let mut value: u64 = 0;
            for &b in bytes {
                value = (value << 8) | (b as u64);
            }
            serde_json::json!({
                "type": "number",
                "decimal": value,
                "hex": format!("0x{}", hex_str),
                "bytes": bytes.len()
            })
        } else if bytes.len() == 256 {
            // Likely a bloom filter
            serde_json::json!({
                "type": "bloom",
                "hex": format!("0x{}...", &hex_str[..64]),
                "bytes": bytes.len()
            })
        } else {
            // Generic bytes
            let preview_len = bytes.len().min(32);
            serde_json::json!({
                "type": "bytes",
                "hex": format!("0x{}...", &hex_str[..preview_len * 2]),
                "bytes": bytes.len()
            })
        };

        Ok(interpretation)
    }
}

fn dump_mdbx_readable(datadir: &Path, output: &Path) -> Result<()> {
    let db_path = datadir.join("db");

    if !db_path.exists() {
        return Ok(());
    }

    // Get absolute paths for abbreviation
    let datadir_abs = datadir.canonicalize().unwrap_or(datadir.to_path_buf());
    let output_abs = output.canonicalize().unwrap_or(output.to_path_buf());

    println!("MDBX Database:");

    match MdbxAnalyzer::new(datadir) {
        Ok(analyzer) => {
            match analyzer.dump_all_data(false) {
                Ok(all_data) => {
                    for (table_name, entries) in all_data {
                        if entries.is_empty() {
                            continue;
                        }

                        let filename = output.join(format!("readable_mdbx_{}.json", table_name));
                        let json = serde_json::to_string_pretty(&entries)?;
                        fs::write(&filename, json)?;

                        let filename_abs = filename.canonicalize().unwrap_or(filename.clone());
                        let db_path_abs = datadir.join("db").canonicalize().unwrap_or(datadir.join("db"));

                        println!("parsed {} entries from {}", entries.len(), table_name);
                        println!("- out: {}", abbreviate_path(&filename_abs, &datadir_abs, &output_abs));
                        println!("- src: {}", abbreviate_path(&db_path_abs, &datadir_abs, &output_abs));
                    }
                }
                Err(_e) => {
                    println!("  [ERR] Failed to dump MDBX data");
                }
            }
        }
        Err(_e) => {
            println!("  [ERR] Failed to open MDBX database");
        }
    }

    println!();
    Ok(())
}

fn dump_static_files_readable(datadir: &Path, output: &Path) -> Result<()> {
    let static_files_path = datadir.join("static_files");

    if !static_files_path.exists() {
        return Ok(());
    }

    // Get absolute paths for abbreviation
    let datadir_abs = datadir.canonicalize().unwrap_or(datadir.to_path_buf());
    let output_abs = output.canonicalize().unwrap_or(output.to_path_buf());

    println!("Static Files:");

    match StaticFileAnalyzer::new(datadir) {
        Ok(analyzer) => {
            match analyzer.dump_all_headers() {
                Ok((headers, source_files)) => {
                    if !headers.is_empty() {
                        let filename = output.join("readable_static_file_headers.json");
                        let json = serde_json::to_string_pretty(&headers)?;
                        fs::write(&filename, json)?;

                        let filename_abs = filename.canonicalize().unwrap_or(filename.clone());

                        println!("parsed {} headers", headers.len());
                        println!("- out: {}", abbreviate_path(&filename_abs, &datadir_abs, &output_abs));
                        for src_file in source_files {
                            let src_file_abs = src_file.canonicalize().unwrap_or(src_file.clone());
                            println!("- src: {}", abbreviate_path(&src_file_abs, &datadir_abs, &output_abs));
                        }
                    }
                }
                Err(_e) => {
                    // Silent failure
                }
            }
        }
        Err(_e) => {
            // Silent failure
        }
    }

    println!();
    Ok(())
}

// Ordinal entry structure: 144 bytes per entry
#[derive(Debug)]
struct OrdinalEntry {
    _digest: [u8; 32],     // Block digest/hash (bytes 0-31)
    value_offset: u64,     // Offset in freezer-value file (bytes 32-39)
    value_size: u64,       // Size of value data (bytes 40-47)
}

fn parse_freezer_blocks_with_ordinal(ordinal_path: &Path, value_path: &Path) -> Result<Vec<ReadableBlock>> {
    // Read ordinal file
    let ordinal_data = fs::read(ordinal_path)?;

    if ordinal_data.len() < 8 {
        eyre::bail!("Ordinal file too small");
    }

    // Check CWIC magic
    if &ordinal_data[0..4] != b"CWIC" {
        eyre::bail!("Ordinal file: invalid magic");
    }

    // Skip 48-byte header
    let mut offset = 48;
    let mut entries = Vec::new();

    // Read all ordinal entries (144 bytes each = 9 rows of 16 bytes)
    while offset + 144 <= ordinal_data.len() {
        let entry_data = &ordinal_data[offset..offset + 144];

        // Check if first row is all zeros (end of entries)
        if entry_data[0..16].iter().all(|&b| b == 0) {
            break;
        }

        // Parse ordinal entry structure (9 rows of 16 bytes)
        // Row 0 (bytes 0-15): metadata
        // Row 1 (bytes 16-31): contains offset and size
        //   - Bytes 22-23 (row1 offset 6-7): offset in value file (big-endian u16)
        //   - Bytes 26-27 (row1 offset 10-11): size (big-endian u16)

        // Extract offset from row 1, bytes 6-7 (entry_data offset 22-23)
        let value_offset = u16::from_be_bytes([
            entry_data[22], entry_data[23]
        ]) as u64;

        // Extract size from row 1, bytes 10-11 (entry_data offset 26-27)
        let value_size = u16::from_be_bytes([
            entry_data[26], entry_data[27]
        ]) as u64;

        // We don't have digest in this ordinal format, use dummy
        let _digest = [0u8; 32];

        entries.push(OrdinalEntry {
            _digest,
            value_offset,
            value_size,
        });

        offset += 144;
    }

    // Read value file
    let value_data_compressed = fs::read(value_path)?;

    if value_data_compressed.len() < 8 {
        eyre::bail!("Value file too small");
    }

    // Check CWIC magic
    if &value_data_compressed[0..4] != b"CWIC" {
        eyre::bail!("Value file: invalid magic");
    }

    // The value file contains multiple zstd frames (one per block)
    // Each entry in ordinal points to a zstd frame offset
    let compressed_data = &value_data_compressed[8..]; // Skip CWIC header

    // Parse blocks using ordinal entries
    let mut blocks = Vec::new();

    use std::io::Read;
    for entry in entries.iter() {
        let start_offset = entry.value_offset as usize;
        let frame_size = entry.value_size as usize;

        if start_offset + frame_size > compressed_data.len() {
            continue;
        }

        // Extract this block's zstd frame
        let compressed_frame = &compressed_data[start_offset..start_offset + frame_size];

        // Check for zstd magic
        if compressed_frame.len() < 4 || compressed_frame[0..4] != [0x28, 0xB5, 0x2F, 0xFD] {
            continue;
        }

        // Decompress this specific frame
        if let Ok(mut decoder) = ruzstd::StreamingDecoder::new(compressed_frame) {
            let mut decompressed = Vec::new();
            if decoder.read_to_end(&mut decompressed).is_ok() {
                // Parse the decompressed block
                if let Ok(block) = parse_single_rlp_block(&decompressed) {
                    blocks.push(block);
                }
            }
        }
    }

    Ok(blocks)
}

fn parse_cache_blocks(key_path: &Path, value_path: &Path) -> Result<Vec<ReadableBlock>> {
    // Read key file to find block heights
    let key_data = fs::read(key_path)?;

    if key_data.len() < 8 {
        eyre::bail!("Key file too small");
    }

    // Check CWIC magic
    if &key_data[0..4] != b"CWIC" {
        eyre::bail!("Key file: invalid magic");
    }

    // Find all block heights by searching for the height marker pattern
    // Pattern: 00 00 00 00 00 00 00 [HEIGHT] [32-byte digest]
    let mut heights_and_digests = Vec::new();
    let mut offset = 8;

    while offset + 40 < key_data.len() {
        // Look for height marker (7 zeros followed by non-zero byte)
        if key_data[offset..offset+7] == [0, 0, 0, 0, 0, 0, 0] && key_data[offset+7] != 0 {
            let height = key_data[offset+7] as u64;

            // Next 32 bytes should be digest
            if offset + 8 + 32 <= key_data.len() {
                let mut digest = [0u8; 32];
                digest.copy_from_slice(&key_data[offset+8..offset+40]);
                heights_and_digests.push((height, digest));
            }
        }

        offset += 1;
    }

    // Read value file
    let value_data = fs::read(value_path)?;

    if value_data.len() < 8 {
        eyre::bail!("Value file too small");
    }

    // Check CWIC magic
    if &value_data[0..4] != b"CWIC" {
        eyre::bail!("Value file: invalid magic");
    }

    // Skip CWIC header
    let payload = &value_data[8..];

    // Parse all RLP blocks from the payload
    // Blocks are stored sequentially in RLP format
    let mut blocks = Vec::new();
    let mut offset = 0;

    while offset < payload.len() {
        // Try to parse a block at this offset
        match parse_single_rlp_block(&payload[offset..]) {
            Ok(block) => {
                let block_size = block.raw_size_bytes;
                blocks.push(block);
                offset += block_size;

                // Safety check
                if block_size == 0 {
                    break;
                }
            }
            Err(_) => {
                // Try to skip to next potential block start
                // Look for RLP list marker (0xf9 for long list)
                let mut found = false;
                for i in 1..100 {
                    if offset + i >= payload.len() {
                        break;
                    }
                    if payload[offset + i] == 0xf9 {
                        offset += i;
                        found = true;
                        break;
                    }
                }
                if !found {
                    break;
                }
            }
        }

        // Safety limit
        if blocks.len() >= 1000 {
            break;
        }
    }

    Ok(blocks)
}

fn parse_single_rlp_block(data: &[u8]) -> Result<ReadableBlock> {
    // Similar to parse_rlp_block but without the outer list wrapper
    if data.len() < 10 {
        eyre::bail!("Data too small to be a valid block");
    }

    // Decode the RLP header
    let header = alloy_rlp::Header::decode(&mut &data[..]).context("Failed to decode RLP header")?;

    if !header.list {
        eyre::bail!("Expected RLP list for block");
    }

    let total_size = header.payload_length + header.length();

    if total_size > data.len() {
        eyre::bail!("Not enough data for block (need {}, have {})", total_size, data.len());
    }

    // The data contains the block's payload
    let block_payload = &data[header.length()..total_size];
    let mut cursor = block_payload;

    // Decode the inner list (the actual block structure)
    let inner_header = alloy_rlp::Header::decode(&mut &cursor[..]).context("Failed to decode inner list header")?;

    if !inner_header.list {
        eyre::bail!("Expected RLP list for inner block");
    }

    // Skip the inner list header
    cursor = &cursor[inner_header.length()..];

    // Parse Tempo block structure: [general_gas_limit, shared_gas_limit, timestamp_millis_part, inner_header, txs, ommers]
    let general_gas_limit = u64::decode(&mut cursor).context("Failed to decode general_gas_limit")?;
    let shared_gas_limit = u64::decode(&mut cursor).context("Failed to decode shared_gas_limit")?;
    let timestamp_millis_part = u64::decode(&mut cursor).context("Failed to decode timestamp_millis_part")?;

    // Field 4: inner Ethereum header (as nested list)
    let header = parse_ethereum_header(&mut cursor).context("Failed to parse inner Ethereum header")?;

    // Field 5: transactions list
    let transactions = Vec::new();
    if cursor.len() > 0 {
        if let Ok(tx_list_header) = alloy_rlp::Header::decode(&mut cursor) {
            if tx_list_header.list {
                // Skip transaction parsing for now
                let _ = &cursor[tx_list_header.payload_length..];
            }
        }
    }

    // Field 6: ommers list (usually empty)
    let ommers = Vec::new();

    let block = ReadableBlock {
        format: "Tempo consensus block".to_string(),
        general_gas_limit,
        shared_gas_limit,
        timestamp_millis_part,
        header,
        transactions,
        ommers,
        raw_size_bytes: total_size,
    };

    Ok(block)
}
