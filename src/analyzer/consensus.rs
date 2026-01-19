use crate::types::{KeyInfo, Summary};
use eyre::Result;
use std::path::Path;
use walkdir::WalkDir;

pub struct ConsensusAnalyzer {
    consensus_path: std::path::PathBuf,
}

impl ConsensusAnalyzer {
    pub fn new(datadir: &Path) -> Result<Self> {
        let consensus_path = datadir.join("consensus");
        if !consensus_path.exists() {
            eyre::bail!("Consensus directory not found at: {}", consensus_path.display());
        }

        println!("Found consensus storage at: {}", consensus_path.display());
        Ok(Self { consensus_path })
    }

    pub async fn get_summary(&self) -> Result<Summary> {
        let mut summary = Summary::new();

        println!("Analyzing consensus storage structure...");

        // Walk through all partitions
        for entry in std::fs::read_dir(&self.consensus_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                let dir_name = path.file_name().unwrap().to_str().unwrap().to_string();

                // Calculate total size of partition
                let mut total_size = 0u64;
                let mut file_count = 0u64;

                for file_entry in WalkDir::new(&path).into_iter().filter_map(|e| e.ok()) {
                    if file_entry.file_type().is_file() {
                        if let Ok(metadata) = file_entry.metadata() {
                            total_size += metadata.len();
                            file_count += 1;
                        }
                    }
                }

                println!("  {} - {} files, {} bytes total", dir_name, file_count, total_size);
                summary.add_key(&format!("partition:{}", dir_name), total_size);
            }
        }

        Ok(summary)
    }

    pub async fn get_block(&self, height: u64) -> Result<Option<KeyInfo>> {
        println!("Note: Direct freezer reading requires commonware-storage dependency");
        println!("Block at height {} would be read from engine-finalized_blocks-* partitions", height);
        Ok(None)
    }

    pub async fn list_finalizations(&self, start: u64, end: u64) -> Result<Vec<KeyInfo>> {
        println!("Note: Direct freezer reading requires commonware-storage dependency");
        println!("Finalizations from {} to {} would be read from engine-finalizations-by-height-* partitions", start, end);
        Ok(Vec::new())
    }
}
