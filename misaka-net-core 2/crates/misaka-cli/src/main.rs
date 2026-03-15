//! MISAKA Network CLI
//!
//! Subcommands:
//!   keygen      Generate a new MISAKA wallet keypair
//!   genesis     Generate a genesis.json for testnet
//!   status      Query node status
//!   balance     Query address balance
//!   transfer    Send MISAKA tokens
//!   faucet      Request testnet tokens

use clap::{Parser, Subcommand};
use anyhow::Result;

mod keygen;
mod genesis;
mod rpc_client;
mod transfer;
mod faucet;

#[derive(Parser)]
#[command(name = "misaka-cli", version, about = "MISAKA Network CLI tools")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new wallet keypair
    Keygen {
        #[arg(long, default_value = ".")]
        output: String,
        #[arg(long, default_value = "wallet")]
        name: String,
    },
    /// Generate testnet genesis configuration
    Genesis {
        #[arg(long, default_value = "4")]
        validators: usize,
        #[arg(long, default_value = "10000000000")]
        treasury: u64,
        #[arg(long, default_value = "2")]
        chain_id: u32,
        #[arg(long, default_value = "genesis.json")]
        output: String,
    },
    /// Query node status
    Status {
        #[arg(long, default_value = "http://127.0.0.1:3001")]
        rpc: String,
    },
    /// Query address balance
    Balance {
        address: String,
        #[arg(long, default_value = "http://127.0.0.1:3001")]
        rpc: String,
    },
    /// Send MISAKA tokens
    Transfer {
        /// Sender key file path (e.g. alice.key.json)
        #[arg(long)]
        from: String,
        /// Recipient address (e.g. msk1abc...)
        #[arg(long)]
        to: String,
        /// Amount to send (base units)
        #[arg(long)]
        amount: u64,
        /// Transaction fee
        #[arg(long, default_value = "100")]
        fee: u64,
        /// Node RPC URL
        #[arg(long, default_value = "http://127.0.0.1:3001")]
        rpc: String,
    },
    /// Request testnet tokens from faucet
    Faucet {
        /// Recipient address
        address: String,
        /// Node RPC URL
        #[arg(long, default_value = "http://127.0.0.1:3001")]
        rpc: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { output, name } => keygen::run(&output, &name)?,
        Commands::Genesis { validators, treasury, chain_id, output } => genesis::run(validators, treasury, chain_id, &output)?,
        Commands::Status { rpc } => rpc_client::get_status(&rpc).await?,
        Commands::Balance { address, rpc } => rpc_client::get_balance(&rpc, &address).await?,
        Commands::Transfer { from, to, amount, fee, rpc } => transfer::run(&from, &to, amount, fee, &rpc).await?,
        Commands::Faucet { address, rpc } => faucet::run(&address, &rpc).await?,
    }

    Ok(())
}
