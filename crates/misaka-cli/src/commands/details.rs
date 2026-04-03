//! CLI `details` command.

use clap::Args;

#[derive(Debug, Args)]
pub struct DetailsArgs {
    /// Subcommand-specific arguments
    #[clap(trailing_var_arg = true)]
    pub args: Vec<String>,
}
