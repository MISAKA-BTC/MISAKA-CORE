//! CLI `wallet` command.

use clap::Args;

#[derive(Debug, Args)]
pub struct WalletArgs {
    /// Subcommand-specific arguments
    #[clap(trailing_var_arg = true)]
    pub args: Vec<String>,
}
