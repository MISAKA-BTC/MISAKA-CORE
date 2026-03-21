use anyhow::{bail, Context};
use clap::{Parser, ValueEnum};
use std::env;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

#[derive(Clone, Debug, ValueEnum)]
enum LauncherProfile {
    Public,
    Seed,
    Validator,
}

#[derive(Debug, Parser)]
#[command(name = "misaka-launcher", version, about = "Launch a packaged MISAKA node")]
struct Cli {
    /// Which packaged profile to start.
    #[arg(long, value_enum, default_value = "public")]
    profile: LauncherProfile,

    /// Override the node config path.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Override the node binary path.
    #[arg(long, value_name = "PATH")]
    node_bin: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let exe_path = env::current_exe().context("failed to resolve launcher path")?;
    let base_dir = exe_path
        .parent()
        .map(Path::to_path_buf)
        .context("launcher has no parent directory")?;
    let node_bin = cli
        .node_bin
        .unwrap_or_else(|| base_dir.join(binary_name("misaka-node")));
    let config_path = cli
        .config
        .unwrap_or_else(|| base_dir.join("config").join(profile_config_name(&cli.profile)));

    if !node_bin.exists() {
        return exit_with_pause(anyhow::anyhow!(
            "misaka-node binary not found: {}",
            node_bin.display()
        ));
    }
    if !config_path.exists() {
        return exit_with_pause(anyhow::anyhow!(
            "config file not found: {}",
            config_path.display()
        ));
    }

    env::set_current_dir(&base_dir)
        .with_context(|| format!("failed to switch into '{}'", base_dir.display()))?;

    println!("MISAKA launcher");
    println!("  profile : {}", profile_label(&cli.profile));
    println!("  binary  : {}", node_bin.display());
    println!("  config  : {}", config_path.display());
    println!();

    let status = Command::new(&node_bin)
        .arg("--config")
        .arg(&config_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("failed to start '{}'", node_bin.display()))?;

    handle_exit(status)
}

fn handle_exit(status: ExitStatus) -> anyhow::Result<()> {
    if status.success() {
        Ok(())
    } else {
        exit_with_pause(anyhow::anyhow!("misaka-node exited with status {}", status))
    }
}

fn exit_with_pause(error: anyhow::Error) -> anyhow::Result<()> {
    eprintln!("ERROR: {error}");
    eprintln!("Press Enter to exit...");
    let mut buf = [0u8; 1];
    let _ = io::stdin().read(&mut buf).ok();
    bail!(error)
}

fn binary_name(base: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

fn profile_config_name(profile: &LauncherProfile) -> &'static str {
    match profile {
        LauncherProfile::Public => "public-node.toml",
        LauncherProfile::Seed => "seed-node.toml",
        LauncherProfile::Validator => "validator-node.toml",
    }
}

fn profile_label(profile: &LauncherProfile) -> &'static str {
    match profile {
        LauncherProfile::Public => "public",
        LauncherProfile::Seed => "seed",
        LauncherProfile::Validator => "validator",
    }
}
