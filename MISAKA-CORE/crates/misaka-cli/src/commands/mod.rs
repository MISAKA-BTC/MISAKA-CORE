//! # CLI Command Registry
//!
//! Kaspa-aligned CLI with 35+ commands covering all node functionality.
//! All commands use PQ-native types (ML-DSA-65 addresses, SHA3-256 hashes).

pub mod account;
pub mod address;
pub mod balance;
pub mod broadcast;
pub mod connect;
pub mod details;
pub mod disconnect;
pub mod estimate;
pub mod export_cmd;
pub mod help;
pub mod history;
pub mod import_cmd;
pub mod list;
pub mod message;
pub mod metrics;
pub mod monitor;
pub mod network;
pub mod node;
pub mod ping;
pub mod rpc;
pub mod select;
pub mod send;
pub mod server;
pub mod settings;
pub mod sign;
pub mod start;
pub mod stop;
pub mod sweep;
pub mod track;
pub mod transfer;
pub mod wallet;

use clap::Subcommand;

/// All CLI subcommands.
#[derive(Debug, Subcommand)]
pub enum CliCommand {
    // ── Key / Account Management ──
    /// Create or manage accounts
    Account(account::AccountArgs),
    /// Show addresses for the active account
    Address(address::AddressArgs),
    /// Open or create a wallet
    Wallet(wallet::WalletArgs),
    /// Import a wallet, private key, or mnemonic
    Import(import_cmd::ImportArgs),
    /// Export wallet or private key
    Export(export_cmd::ExportArgs),
    /// Select active account
    Select(select::SelectArgs),
    /// List all accounts in the wallet
    List(list::ListArgs),

    // ── Transactions ──
    /// Send MISAKA to an address
    Send(send::SendArgs),
    /// Transfer between own accounts
    Transfer(transfer::TransferArgs),
    /// Sign a PSMT (Partially Signed MISAKA Transaction)
    Sign(sign::SignArgs),
    /// Broadcast a signed transaction
    Broadcast(broadcast::BroadcastArgs),
    /// Estimate transaction fee
    Estimate(estimate::EstimateArgs),
    /// Sweep all UTXOs to a single address
    Sweep(sweep::SweepArgs),

    // ── Balance / UTXO ──
    /// Show balance for active account or address
    Balance(balance::BalanceArgs),
    /// Show transaction history
    History(history::HistoryArgs),
    /// Show account details (UTXOs, keys, etc.)
    Details(details::DetailsArgs),
    /// Track an address for UTXO changes
    Track(track::TrackArgs),

    // ── Node Operations ──
    /// Connect to a node
    Connect(connect::ConnectArgs),
    /// Disconnect from the current node
    Disconnect(disconnect::DisconnectArgs),
    /// Node information and status
    Node(node::NodeArgs),
    /// Start the embedded node
    Start(start::StartArgs),
    /// Stop the embedded node
    Stop(stop::StopArgs),
    /// Network information
    Network(network::NetworkArgs),

    // ── Monitoring ──
    /// Show real-time metrics
    Metrics(metrics::MetricsArgs),
    /// Monitor blocks and transactions
    Monitor(monitor::MonitorArgs),
    /// Ping the connected node
    Ping(ping::PingArgs),

    // ── Server ──
    /// Start an RPC server
    Server(server::ServerArgs),
    /// Execute a raw RPC call
    Rpc(rpc::RpcArgs),

    // ── Message Signing (PQ) ──
    /// Sign a message with ML-DSA-65
    Message(message::MessageArgs),

    // ── Settings ──
    /// Configure CLI settings
    Settings(settings::SettingsArgs),

    // ── Help ──
    /// Show extended help
    Help(help::HelpArgs),
}
