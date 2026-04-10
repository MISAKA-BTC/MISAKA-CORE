//! CLI `node` command.

use clap::Args;

#[derive(Debug, Args)]
pub struct NodeArgs {
    /// Subcommand-specific arguments
    #[clap(trailing_var_arg = true)]
    pub args: Vec<String>,
}
