//! CLI `track` command.

use clap::Args;

#[derive(Debug, Args)]
pub struct TrackArgs {
    /// Subcommand-specific arguments
    #[clap(trailing_var_arg = true)]
    pub args: Vec<String>,
}
