use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Summary information about database contents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub total_keys: u64,
    pub key_type_count: HashMap<String, u64>,
    pub key_type_total_size: HashMap<String, u64>,
    pub largest_keys: Vec<KeySizeInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height_range: Option<HeightRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_blocks: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySizeInfo {
    pub key: String,
    pub key_type: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeightRange {
    pub min_height: u64,
    pub max_height: u64,
}

/// Information about a single key-value pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_hex: Option<String>,
    pub key_type: String,
    pub value_size_bytes: usize,
    pub data: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Summary {
    pub fn new() -> Self {
        Self {
            total_keys: 0,
            key_type_count: HashMap::new(),
            key_type_total_size: HashMap::new(),
            largest_keys: Vec::new(),
            height_range: None,
            total_blocks: None,
        }
    }

    pub fn add_key(&mut self, key_type: &str, size: u64) {
        self.total_keys += 1;
        *self.key_type_count.entry(key_type.to_string()).or_insert(0) += 1;
        *self.key_type_total_size.entry(key_type.to_string()).or_insert(0) += size;
    }

    #[allow(dead_code)]
    pub fn update_largest_keys(&mut self, key: String, key_type: String, size: usize, max_keep: usize) {
        self.largest_keys.push(KeySizeInfo {
            key,
            key_type,
            size_bytes: size,
        });

        // Keep sorted by size (descending) and limit to max_keep
        self.largest_keys.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
        if self.largest_keys.len() > max_keep {
            self.largest_keys.truncate(max_keep);
        }
    }

    pub fn print_summary(&self) {
        println!("=== SUMMARY ===\n");
        println!("Total Keys: {}", self.total_keys);

        if let Some(range) = &self.height_range {
            println!("Height Range: {} to {}", range.min_height, range.max_height);
        }

        if let Some(total_blocks) = self.total_blocks {
            println!("Total Blocks: {}", total_blocks);
        }

        println!("\nKey Type Distribution:");
        let mut types: Vec<_> = self.key_type_count.iter().collect();
        types.sort_by_key(|(name, _)| *name);

        for (key_type, count) in types {
            let total_size = self.key_type_total_size.get(key_type).unwrap_or(&0);
            let avg_size = if *count > 0 {
                *total_size / *count
            } else {
                0
            };
            println!(
                "  {:<30} : {:>8} keys | Total: {:>12} bytes | Avg: {:>8} bytes",
                key_type, count, total_size, avg_size
            );
        }

        if !self.largest_keys.is_empty() {
            println!("\nTop {} Largest Keys:", self.largest_keys.len());
            for (i, key_info) in self.largest_keys.iter().enumerate() {
                println!(
                    "  {}. {} bytes - {} ({})",
                    i + 1,
                    key_info.size_bytes,
                    key_info.key,
                    key_info.key_type
                );
            }
        }
    }
}

impl Default for Summary {
    fn default() -> Self {
        Self::new()
    }
}
