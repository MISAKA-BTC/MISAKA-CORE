//! MISAKA Network CLI
//!
//! Subcommands:
//!   keygen        Generate a new MISAKA wallet keypair
//!   genesis       Generate a genesis.json for testnet
//!   status        Query node status
//!   balance       Query address balance
//!   transfer      Send MISAKA tokens (v1-v3 ring signature path)
//!   ct-transfer   Send MISAKA tokens confidentially (v4 Q-DAG-CT, amounts + sender hidden)
//!   faucet        Request testnet tokens (auto-registers UTXO with --wallet)

use anyhow::Result;
use clap::{Parser, Subcommand};

mod faucet;
mod genesis;
mod keygen;
mod rpc_client;
mod transfer;
mod confidential_transfer;
pub mod wallet_state;

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
    /// Send MISAKA tokens (supports multiple sends via UTXO tracking)
    Transfer {
        /// Sender key file path (e.g. wallet1.key.json)
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
        /// Wallet key file (optional — enables auto UTXO tracking for transfers)
        #[arg(long)]
        wallet: Option<String>,
        /// Explicit spending pubkey hex for the receiving output
        #[arg(long = "spending-pubkey")]
        spending_pubkey: Option<String>,
        /// Node RPC URL
        #[arg(long, default_value = "http://127.0.0.1:3001")]
        rpc: String,
    },
    /// Send MISAKA tokens with Q-DAG-CT confidential transaction (amounts + sender hidden)
    CtTransfer {
        /// Sender key file path (e.g. wallet1.key.json)
        #[arg(long)]
        from: String,
        /// Recipient ML-KEM-768 public key (hex). Use the ml_kem_pk from their .pub.json
        #[arg(long)]
        to_kem_pk: String,
        /// Amount to send (base units — hidden from chain observers)
        #[arg(long)]
        amount: u64,
        /// Transaction fee (hidden from chain, must be >= 100)
        #[arg(long, default_value = "100")]
        fee: u64,
        /// Chain ID
        #[arg(long, default_value = "2")]
        chain_id: u32,
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
        Commands::Genesis {
            validators,
            treasury,
            chain_id,
            output,
        } => genesis::run(validators, treasury, chain_id, &output)?,
        Commands::Status { rpc } => rpc_client::get_status(&rpc).await?,
        Commands::Balance { address, rpc } => rpc_client::get_balance(&rpc, &address).await?,
        Commands::Transfer {
            from,
            to,
            amount,
            fee,
            rpc,
        } => transfer::run(&from, &to, amount, fee, &rpc).await?,
        Commands::Faucet {
            address,
            rpc,
            wallet,
            spending_pubkey,
        } => {
            faucet::run(
                &address,
                &rpc,
                wallet.as_deref(),
                spending_pubkey.as_deref(),
            )
            .await?
        }
        Commands::CtTransfer {
            from,
            to_kem_pk,
            amount,
            fee,
            chain_id,
            rpc,
        } => {
            confidential_transfer::run(&from, &to_kem_pk, amount, fee, chain_id, &rpc).await?
        }
    }

    Ok(())
}
