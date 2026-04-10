//! MISAKA Network CLI
//!
//! # Commands
//!
//!   send          Send tokens (transparent, ML-DSA-65)
//!   keygen        Generate a new wallet keypair
//!   genesis       Generate genesis configuration
//!   status        Query node status
//!   balance       Query address balance
//!   faucet        Request testnet tokens
//!   check-stake   Check validator staking status on Solana (tamper-proof)
//!
//! # Examples
//!
//! ```bash
//! misaka-cli send msk1abc... 1.5                        # transparent (ML-DSA-65)
//! misaka-cli check-stake                                 # check your validator stake
//! ```

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod check_stake;
mod faucet;
mod genesis;
mod keygen;
mod public_transfer;
mod rpc_client;
mod send;
mod setup_validator;
pub mod wallet_state;

#[derive(Parser)]
#[command(
    name = "misaka-cli",
    version,
    about = "MISAKA Network CLI",
    long_about = "Post-quantum, privacy-focused blockchain CLI.\n\n\
                  Send tokens:  misaka-cli send <ADDRESS> <AMOUNT>"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // ═══════════════════════════════════════════════════════
    //  Primary command: unified send
    // ═══════════════════════════════════════════════════════
    /// Send MISAKA tokens to an address (transparent, ML-DSA-65).
    Send {
        /// Recipient address (e.g. msk1abc...)
        #[arg(index = 1)]
        to: String,

        /// Amount in MISAKA (supports decimals, e.g. 1.5)
        #[arg(index = 2)]
        amount: f64,

        /// Wallet key file path
        #[arg(short = 'w', long = "wallet", default_value = "wallet.key.json")]
        wallet: String,

        /// Transaction fee in MISAKA (default: 0.0001)
        #[arg(long, default_value = "0.0001")]
        fee: f64,

        /// Chain ID
        #[arg(long, default_value = "2")]
        chain_id: u32,

        /// Node RPC URL
        #[arg(long, default_value = "http://127.0.0.1:3001")]
        rpc: String,

        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },

    // ═══════════════════════════════════════════════════════
    //  Utility commands
    // ═══════════════════════════════════════════════════════
    /// Generate a new wallet keypair
    Keygen {
        #[arg(long, default_value = ".")]
        output: String,
        #[arg(long, default_value = "wallet")]
        name: String,
        /// Chain ID (1=mainnet, 2=testnet). Determines address checksum.
        #[arg(long, default_value = "2")]
        chain_id: u32,
    },

    /// Generate genesis configuration
    Genesis {
        #[arg(long, default_value = "4")]
        validators: usize,
        #[arg(long, default_value = "10000000000")]
        treasury: u64,
        #[arg(long, default_value = "2")]
        chain_id: u32,
        #[arg(long, default_value = "genesis.json")]
        output: String,
        /// Treasury one-time address (hex, 32 bytes)
        #[arg(long)]
        treasury_address: Option<String>,
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

    /// Request testnet tokens from faucet
    Faucet {
        /// Recipient address
        address: String,
        /// Wallet key file (optional — enables auto UTXO tracking)
        #[arg(long)]
        wallet: Option<String>,
        /// Explicit spending pubkey hex
        #[arg(long = "spending-pubkey")]
        spending_pubkey: Option<String>,
        /// Node RPC URL
        #[arg(long, default_value = "http://127.0.0.1:3001")]
        rpc: String,
    },

    /// List wallet UTXOs and balance
    #[command(name = "wallet-info")]
    WalletInfo {
        /// Wallet key file path
        #[arg(short = 'w', long = "wallet", default_value = "wallet.key.json")]
        wallet: String,
    },

    /// Validate wallet state integrity
    #[command(name = "wallet-validate")]
    WalletValidate {
        /// Wallet key file path
        #[arg(short = 'w', long = "wallet", default_value = "wallet.key.json")]
        wallet: String,
        /// Auto-fix issues (recalculate balance, prune spent)
        #[arg(long)]
        fix: bool,
    },

    // ═══════════════════════════════════════════════════════
    //  Legacy commands (hidden, backward compat)
    // ═══════════════════════════════════════════════════════
    /// [deprecated] Use `send` instead
    #[command(hide = true)]
    Transfer {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value = "100")]
        fee: u64,
        #[arg(long, default_value = "http://127.0.0.1:3001")]
        rpc: String,
    },

    // REMOVED: CtTransfer — confidential transfers deprecated in v1.0.
    /// [deprecated] Use `send` instead (transparent is default)
    #[command(hide = true)]
    PublicTransfer {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value = "100")]
        fee: u64,
        #[arg(long, default_value = "http://127.0.0.1:3001")]
        rpc: String,
    },

    // ═══════════════════════════════════════════════════════
    //  Validator Staking Commands
    // ═══════════════════════════════════════════════════════
    /// Check validator staking status on Solana mainnet.
    ///
    /// Reads on-chain data directly from Solana to verify the amount of MISAKA
    /// staked for this validator. Data is tamper-proof — only the staking
    /// program can modify it.
    ///
    /// Example: misaka-cli check-stake --l1-key <HEX>
    ///          misaka-cli check-stake --key-file data/l1-public-key.json
    CheckStake {
        /// L1 public key (hex, 64 chars). If not provided, reads from --key-file.
        #[arg(long)]
        l1_key: Option<String>,
        /// Path to l1-public-key.json (default: data/l1-public-key.json)
        #[arg(long, default_value = "data/l1-public-key.json")]
        key_file: String,
    },

    /// Interactive validator setup — create wallet, generate keys, register as SR21 candidate.
    ///
    /// Flow:
    ///   1. Create or load MISAKA wallet (ML-DSA-65)
    ///   2. Generate L1 validator key (for block signing)
    ///   3. Display Solana staking instructions (10M+ MISAKA required)
    ///   4. Verify stake on-chain
    ///   5. Output misaka-node startup command
    ///
    /// Example: misaka-cli setup-validator --data-dir ./data
    SetupValidator {
        /// Data directory for keys and config
        #[arg(long, default_value = ".")]
        data_dir: String,
        /// Chain ID (1=mainnet, 2=testnet)
        #[arg(long, default_value_t = 2)]
        chain_id: u32,
        /// Validator index (0-20 for SR21)
        #[arg(long, default_value_t = 0)]
        validator_index: usize,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        // ── Unified send ──
        Commands::Send {
            to,
            amount,
            wallet,
            fee,
            chain_id,
            rpc,
            yes,
        } => {
            let amount_base = send::parse_amount(amount)?;
            let fee_base = send::parse_amount(fee)?;
            let mode = send::resolve_mode(false);

            send::run(send::SendArgs {
                to,
                amount_raw: amount,
                amount_base,
                fee_base,
                mode,
                wallet_path: wallet,
                rpc_url: rpc,
                chain_id,
                skip_confirm: yes,
            })
            .await?
        }

        // ── Utility commands ──
        Commands::Keygen {
            output,
            name,
            chain_id,
        } => keygen::run(&output, &name, chain_id)?,

        Commands::Genesis {
            validators,
            treasury,
            chain_id,
            output,
            treasury_address,
        } => genesis::run(
            validators,
            treasury,
            chain_id,
            &output,
            treasury_address.as_deref(),
        )?,

        Commands::Status { rpc } => rpc_client::get_status(&rpc).await?,

        Commands::Balance { address, rpc } => rpc_client::get_balance(&rpc, &address).await?,

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

        Commands::WalletInfo { wallet } => wallet_info(&wallet)?,

        Commands::WalletValidate { wallet, fix } => wallet_validate(&wallet, fix)?,

        // ── Legacy compat (hidden, emit deprecation warning) ──
        // ── Legacy compat (hidden, emit deprecation warning) ──
        Commands::Transfer {
            from,
            to,
            amount,
            fee,
            rpc,
        } => {
            eprintln!(
                "⚠  `transfer` is deprecated. Use: misaka-cli send {} {}",
                to, amount
            );
            // Run as transparent transfer instead
            // Phase 2b: default chain_id=2 (testnet); mainnet will require explicit --chain-id
            // Phase 2c-A: genesis_hash [0;32] default for CLI — user should pass --genesis-hash
            public_transfer::run(&from, &to, amount, fee, &rpc, 2, [0u8; 32]).await?
        }

        // REMOVED: CtTransfer command — confidential transfers deprecated.
        Commands::PublicTransfer {
            from,
            to,
            amount,
            fee,
            rpc,
        } => {
            eprintln!(
                "⚠  `public-transfer` is deprecated. Use: misaka-cli send {} {} -w {}",
                to, amount, from
            );
            // Phase 2b: default chain_id=2 (testnet); mainnet will require explicit --chain-id
            // Phase 2c-A: genesis_hash [0;32] default for CLI — user should pass --genesis-hash
            public_transfer::run(&from, &to, amount, fee, &rpc, 2, [0u8; 32]).await?
        }

        // ── Validator staking ──
        Commands::CheckStake { l1_key, key_file } => {
            let key = match l1_key {
                Some(k) => k,
                None => {
                    let path = std::path::Path::new(&key_file);
                    if !path.exists() {
                        anyhow::bail!(
                            "L1 key file not found: {}\n\
                             Use --l1-key <HEX> or --key-file <PATH>",
                            key_file
                        );
                    }
                    let raw = std::fs::read_to_string(path).context("failed to read key file")?;
                    let parsed: serde_json::Value =
                        serde_json::from_str(&raw).context("failed to parse key file JSON")?;
                    parsed["l1PublicKey"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("l1PublicKey not found in key file"))?
                        .to_string()
                }
            };
            check_stake::run(&key).await?
        }
        Commands::SetupValidator {
            data_dir,
            chain_id,
            validator_index,
        } => setup_validator::run(&data_dir, chain_id, validator_index).await?,
    }

    Ok(())
}

/// Display wallet UTXOs and balance summary.
fn wallet_info(wallet_path: &str) -> Result<()> {
    let state_path = wallet_state::WalletState::state_path(wallet_path);
    if !state_path.exists() {
        println!("No wallet state found at: {}", state_path.display());
        println!("Hint: Run a faucet command with --wallet to create state.");
        return Ok(());
    }

    let json = std::fs::read_to_string(&state_path)?;
    let state: wallet_state::WalletState = serde_json::from_str(&json)?;

    println!("╔═══════════════════════════════════════════════╗");
    println!("║  MISAKA Wallet Info                           ║");
    println!("╚═══════════════════════════════════════════════╝");
    println!();
    println!("  Name:      {}", state.wallet_name);
    println!("  Address:   {}", state.master_address);
    println!(
        "  Balance: {} MISAKA ({} base units)",
        state.balance as f64 / 1_000_000.0,
        state.balance
    );
    println!("  Next child index: {}", state.next_child_index);
    println!();

    let unspent: Vec<_> = state.utxos.iter().filter(|u| !u.spent).collect();
    let spent: Vec<_> = state.utxos.iter().filter(|u| u.spent).collect();

    println!("  Unspent UTXOs: {}", unspent.len());
    for u in &unspent {
        println!(
            "    {}..:{} → {} MISAKA (child #{})",
            &u.tx_hash[..u.tx_hash.len().min(16)],
            u.output_index,
            u.amount,
            u.child_index,
        );
    }

    if !spent.is_empty() {
        println!();
        println!("  Spent UTXOs: {}", spent.len());
    }

    println!();
    println!("  State file: {}", state_path.display());

    Ok(())
}

/// Validate and optionally fix wallet state.
fn wallet_validate(wallet_path: &str, fix: bool) -> Result<()> {
    let state_path = wallet_state::WalletState::state_path(wallet_path);
    if !state_path.exists() {
        println!("No wallet state found at: {}", state_path.display());
        return Ok(());
    }

    let json = std::fs::read_to_string(&state_path)?;
    let mut state: wallet_state::WalletState = serde_json::from_str(&json)?;

    println!("🔍 Validating wallet state: {}", state_path.display());
    println!();

    let warnings = state.validate();

    if warnings.is_empty() {
        println!("  ✅ Wallet state is consistent.");
    } else {
        for w in &warnings {
            println!("  ⚠  {}", w);
        }
    }

    if fix {
        println!();
        println!("  🔧 Applying fixes...");
        state.recalculate_balance();
        state.prune_spent();
        state.save(wallet_path)?;
        println!("  ✅ Wallet state fixed and saved.");
        println!("  Balance: {} MISAKA", state.balance);
        println!(
            "  UTXOs: {} total ({} unspent)",
            state.utxos.len(),
            state.unspent_utxos().len()
        );
    }

    Ok(())
}
