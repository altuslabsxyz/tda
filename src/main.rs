use clap::{Parser, Subcommand, CommandFactory};
use clap_complete::{generate, Shell};
use eyre::Result;
use std::path::PathBuf;

mod analyzer;
mod commands;
mod types;

const BANNER: &str = r#"

░▒▓████████▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░
   ░▒▓█▓▒░   ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░
"#;

/// Tempo Database Analyzer (TDA)
///
/// A CLI tool to analyze and extract data from Tempo databases including
/// MDBX (execution state), Commonware Freezer (consensus data), and
/// NippyJar static files (historical blockchain data).
#[derive(Parser)]
#[command(name = "tda")]
#[command(version, about, long_about = None)]
#[command(before_help = BANNER)]
struct Cli {
    /// Path to the Tempo data directory
    #[arg(short, long, value_name = "DIR")]
    datadir: Option<PathBuf>,

    /// Output directory for JSON files
    #[arg(short, long, value_name = "DIR", default_value = "./tda_output")]
    output: PathBuf,

    /// Skip full data dump (only generate summary)
    #[arg(long)]
    skip_full_dump: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Extract and analyze MDBX database (execution state)
    #[command(alias = "m")]
    Mdbx {
        #[command(subcommand)]
        action: Option<MdbxAction>,
    },

    /// Extract and analyze Commonware consensus storage
    #[command(alias = "c")]
    Consensus {
        #[command(subcommand)]
        action: Option<ConsensusAction>,
    },

    /// Extract and analyze NippyJar static files (historical data)
    #[command(alias = "s")]
    StaticFile {
        #[command(subcommand)]
        action: Option<StaticFileAction>,
    },

    /// Extract all storage systems (comprehensive analysis)
    #[command(alias = "a")]
    All,

    /// Dump raw hex data from storage files
    #[command(alias = "r")]
    RawDump,

    /// Parse and dump human-readable JSON from storage files
    #[command(alias = "p")]
    ReadableDump,

    /// Generate shell completion scripts
    #[command(alias = "comp")]
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum MdbxAction {
    /// List all tables in the database
    ListTables,

    /// Get database statistics and summary
    Summary,

    /// Get block header by number
    GetHeader { block_number: u64 },

    /// Get account state by address
    GetAccount { address: String },

    /// Dump all data from the database
    DumpAll,
}

#[derive(Subcommand)]
enum ConsensusAction {
    /// Get finalized block by height
    GetBlock { height: u64 },

    /// List finalization certificates in a height range
    ListFinalizations {
        #[arg(long)]
        start: u64,
        #[arg(long)]
        end: u64,
    },

    /// Get consensus summary and statistics
    Summary,

    /// Dump all consensus data
    DumpAll,
}

#[derive(Subcommand)]
enum StaticFileAction {
    /// List available segments
    ListSegments,

    /// Get block from static files by number
    GetBlock { block_number: u64 },

    /// Get transaction by hash
    GetTx { tx_hash: String },

    /// Get receipt by transaction hash
    GetReceipt { tx_hash: String },

    /// Get static file summary and statistics
    Summary,

    /// Dump all static file data
    DumpAll,

    /// Dump all headers to JSON
    DumpHeaders,

    /// Dump all transactions to JSON
    DumpTransactions,

    /// Dump all receipts to JSON
    DumpReceipts,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle completions first (no datadir needed)
    if let Commands::Completions { shell } = cli.command {
        let mut cmd = Cli::command();
        generate(shell, &mut cmd, "tda", &mut std::io::stdout());
        return Ok(());
    }

    // For all other commands, datadir is required
    let datadir = cli.datadir.ok_or_else(|| eyre::eyre!("--datadir is required"))?;

    // Print banner
    print_banner();

    // Create output directory
    std::fs::create_dir_all(&cli.output)?;

    // Only print header for non-ReadableDump commands
    match &cli.command {
        Commands::ReadableDump => {
            // ReadableDump prints its own header
        }
        _ => {
            println!("Datadir: {}", datadir.display());
            println!("Output:  {}", cli.output.display());
            if cli.skip_full_dump {
                println!("Mode:    Summary only");
            }
            println!();
        }
    }

    match cli.command {
        Commands::Mdbx { action } => {
            commands::mdbx::handle_command(
                &datadir,
                &cli.output,
                action,
                cli.skip_full_dump,
            )?;
            print_complete(&cli.output);
        }
        Commands::Consensus { action } => {
            commands::consensus::handle_command(
                &datadir,
                &cli.output,
                action,
                cli.skip_full_dump,
            )
            .await?;
            print_complete(&cli.output);
        }
        Commands::StaticFile { action } => {
            commands::static_file::handle_command(
                &datadir,
                &cli.output,
                action,
                cli.skip_full_dump,
            )?;
            print_complete(&cli.output);
        }
        Commands::All => {
            // Run readable dump (parses all data)
            analyzer::readable_dump::dump_readable_files(&datadir, &cli.output)?;

            // Run raw hex dump
            analyzer::raw_dump::dump_raw_files(&datadir, &cli.output)?;

            print_complete(&cli.output);
        }
        Commands::RawDump => {
            analyzer::raw_dump::dump_raw_files(&datadir, &cli.output)?;
            print_complete(&cli.output);
        }
        Commands::ReadableDump => {
            analyzer::readable_dump::dump_readable_files(&datadir, &cli.output)?;
        }
        Commands::Completions { .. } => {
            // Already handled above
            unreachable!()
        }
    }

    Ok(())
}

fn print_complete(output: &std::path::Path) {
    println!();
    println!("Analysis complete. Results saved to: {}", output.display());
}

fn print_banner() {
    println!("{}", BANNER);
}
