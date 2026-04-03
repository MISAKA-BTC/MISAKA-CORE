//! CLI `server` command.

use clap::Args;

#[derive(Debug, Args)]
pub struct ServerArgs {
    /// Subcommand-specific arguments
    #[clap(trailing_var_arg = true)]
    pub args: Vec<String>,
}
