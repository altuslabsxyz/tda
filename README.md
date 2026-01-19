# Tempo Database Analyzer (TDA)

A command-line tool for analyzing and extracting data from Tempo blockchain node storage systems.

## Overview

TDA provides read-only access to all three storage layers used by Tempo nodes:

1. **MDBX Database** - Execution layer state (accounts, storage, blocks)
2. **Commonware Consensus** - Consensus layer data (finalized blocks, certificates, DKG events)
3. **NippyJar Static Files** - Historical blockchain data archives (headers, transactions, receipts)

## Versioning

TDA follows Tempo's versioning scheme. Each TDA release is tagged to match the corresponding Tempo version it supports.

**Current Version**: `v1.0.0-rc.3`
- Tested and verified against Tempo `v1.0.0-rc.3`
- Future releases will be tagged to match new Tempo versions

To use TDA with a specific Tempo version, checkout the corresponding tag:

```bash
git checkout v1.0.0-rc.3
cargo build --release
```

## Installation

### Prerequisites

- Rust 1.91.0 or later
- Git

### Build from Source

```bash
git clone https://github.com/altuslabsxyz/tda.git
cd tda
cargo build --release
```

The binary will be available at `./target/release/tda`.

## Usage

### Finding the Tempo Data Directory

When you run a Tempo node, it creates a data directory containing all blockchain data. The path typically follows this pattern:

```
<tempo-workspace>/localnet-single/<node-address>/
```

For example, if running a local Tempo node:
```
/Users/z/workspace/tempoxyz/benchmark-tempo/tempo/localnet-single/127.0.0.1:8000
```

This directory contains:
- `db/` - MDBX database files
- `consensus/` - Consensus layer data
- `static_files/` - Historical blockchain archives

Use this path as the `--datadir` argument for TDA.

### Basic Syntax

```bash
tda --datadir <DATADIR> [OPTIONS] <COMMAND>
```

### Global Options

- `-d, --datadir <DIR>` - Path to Tempo data directory (required)
- `-o, --output <DIR>` - Output directory for JSON files (default: `./tda_output`)
- `--skip-full-dump` - Generate summaries only, skip full data dumps

### Commands

#### Parse All Data

```bash
# Example with actual Tempo datadir path
tda --datadir /Users/z/workspace/tempoxyz/benchmark-tempo/tempo/localnet-single/127.0.0.1:8000 readable-dump

# Or use a generic path
tda --datadir /path/to/tempo/datadir readable-dump
```

Outputs parsed data from all storage systems in human-readable JSON format.

#### Analyze MDBX Database

```bash
# Get database summary
tda --datadir /path/to/tempo/datadir mdbx summary

# List all tables
tda --datadir /path/to/tempo/datadir mdbx list-tables

# Get account state (TBD)
tda --datadir /path/to/tempo/datadir mdbx get-account 0x1234...

# Get block header
tda --datadir /path/to/tempo/datadir mdbx get-header 100

# Dump all data
tda --datadir /path/to/tempo/datadir mdbx dump-all
```

#### Analyze Consensus Data

```bash
# Get consensus summary
tda --datadir /path/to/tempo/datadir consensus summary

# Get finalized block (TBD)
tda --datadir /path/to/tempo/datadir consensus get-block 42

# List finalization certificates in range (TBD)
tda --datadir /path/to/tempo/datadir consensus list-finalizations --start 0 --end 100

# Dump all consensus data
tda --datadir /path/to/tempo/datadir consensus dump-all
```

#### Analyze Static Files

```bash
# Get static files summary
tda --datadir /path/to/tempo/datadir static-file summary

# List available segments
tda --datadir /path/to/tempo/datadir static-file list-segments

# Get block from static files (TBD)
tda --datadir /path/to/tempo/datadir static-file get-block 100

# Dump all static file data (TBD)
tda --datadir /path/to/tempo/datadir static-file dump-all
```

#### Comprehensive Analysis

```bash
# Analyze all storage systems
tda --datadir /path/to/tempo/datadir all

# Dump raw hex data
tda --datadir /path/to/tempo/datadir raw-dump
```

## Output Format

### Parsed Data Output

When using `readable-dump` or similar commands, TDA outputs:

```
parsed N items from <source>
outdir: /absolute/path/to/output.json
srcdir:
- /absolute/path/to/source/file1
- /absolute/path/to/source/file2
```

### JSON Output Structure

All parsed data is saved as pretty-printed JSON files in the output directory:

- `readable_finalized_blocks.json` - Finalized consensus blocks
- `readable_notarized_blocks.json` - Notarized consensus blocks
- `readable_verified_blocks.json` - Verified consensus blocks
- `readable_finalization_certificates.json` - Finalization certificates with validator signatures
- `readable_dkg_events.json` - DKG (Distributed Key Generation) events
- `readable_static_file_headers.json` - Block headers from static files
- `readable_mdbx_*.json` - MDBX database tables

## Architecture

### Storage Systems

**MDBX Database** (`db/`)
- Stores current execution state (accounts, contract storage, blocks)
- Key-value database using MDBX (Lightning Memory-Mapped Database)
- Contains tables: Headers, Bodies, Account, Storage, etc.

**Commonware Consensus** (`consensus/`)
- Stores consensus layer data using CWIC (Commonware Internal Codec) format
- Two storage types:
  - Freezer: Immutable historical data with ordinal indexing
  - Cache: Recent data with key-value structure
- Contains finalized blocks, finalization certificates, DKG events

**NippyJar Static Files** (`static_files/`)
- Archives historical blockchain data in columnar format
- Optimized for compression and fast random access
- Contains segments for headers, transactions, and receipts

### Data Formats

**CWIC Format**
- Magic bytes: `CWIC` (0x43574943)
- 8-byte header followed by payload
- May use zstd compression for finalized data
- Varint encoding for integers

**NippyJar Format**
- Columnar storage with separate compression per column
- Configuration file (.conf) describes column layout
- Offset file (.off) for random access

**RLP Encoding**
- Recursive Length Prefix encoding for Ethereum data structures
- Used in consensus blocks and static files

## Development

### Project Structure

```
src/
├── analyzer/          # Core analysis logic
│   ├── mdbx.rs       # MDBX database analyzer
│   ├── consensus.rs  # Consensus data analyzer
│   ├── static_file.rs # Static files analyzer
│   ├── readable_dump.rs # Human-readable JSON output
│   └── raw_dump.rs   # Raw hex output
├── commands/         # CLI command handlers
│   ├── mdbx.rs
│   ├── consensus.rs
│   └── static_file.rs
├── types.rs          # Shared data structures
└── main.rs           # CLI entry point
```

### Dependencies

TDA uses Git dependencies for compatibility with Tempo:

- **Reth** (blockchain infrastructure)
  - reth-db, reth-db-api, reth-primitives
  - reth-nippy-jar, reth-storage-errors, reth-provider
- **Tempo** (blockchain primitives)
  - tempo-primitives
- **Commonware** (consensus codecs)
  - commonware-codec, commonware-consensus, commonware-cryptography

### Build Configuration

The project is configured as a standalone Cargo workspace:
- Edition: 2024
- Rust version: 1.91.0
- Build dependencies: vergen, vergen-git2 (for build metadata)

## Troubleshooting

### Clean Build

If you encounter build issues:

```bash
rm -rf Cargo.lock target
cargo build --release
```

### Common Issues

**"Static files directory not found"**
- Ensure the datadir path is correct
- Verify the directory contains a `static_files/` subdirectory

**"Failed to open MDBX database"**
- Check that the node is not currently running (MDBX requires exclusive access for write mode)
- TDA uses read-only mode, so this should be rare

**Build failures with vergen**
- Ensure you're not inside another Cargo workspace
- Try using `bash -c "cd /path/to/tda && cargo build --release"`

## License

MIT OR Apache-2.0
