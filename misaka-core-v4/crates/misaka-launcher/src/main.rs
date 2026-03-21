use anyhow::{anyhow, bail, Context};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::net::{IpAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;

const DEFAULT_SELF_HOST_SEED_ADDR: &str = "127.0.0.1:6690";
const DEFAULT_STARTUP_WAIT_SECS: u64 = 2;

#[derive(Clone, Debug, ValueEnum)]
enum LauncherProfile {
    Public,
    Seed,
    Validator,
}

#[derive(Debug, Args)]
struct StartArgs {
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

#[derive(Debug, Args)]
struct DoctorArgs {
    /// Which packaged profile to inspect.
    #[arg(long, value_enum, default_value = "public")]
    profile: LauncherProfile,

    /// Override the config path to inspect.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct SelfHostArgs {
    /// Override the packaged node binary path.
    #[arg(long, value_name = "PATH")]
    node_bin: Option<PathBuf>,

    /// Override the public-node config path.
    #[arg(long, value_name = "PATH")]
    public_config: Option<PathBuf>,

    /// Override the seed-node config path.
    #[arg(long, value_name = "PATH")]
    seed_config: Option<PathBuf>,

    /// Override the loopback seed address used by the public node.
    #[arg(long, value_name = "HOST:PORT", default_value = DEFAULT_SELF_HOST_SEED_ADDR)]
    seed_addr: String,
}

#[derive(Debug, Subcommand)]
enum LauncherCommand {
    /// Print a local networking checklist for the packaged node profile.
    Doctor(DoctorArgs),
    /// Start a local seed and attach the public node to it.
    SelfHost(SelfHostArgs),
}

#[derive(Debug, Parser)]
#[command(
    name = "misaka-launcher",
    version,
    about = "Launch a packaged MISAKA node"
)]
struct Cli {
    #[command(flatten)]
    start: StartArgs,

    #[command(subcommand)]
    command: Option<LauncherCommand>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PackageConfig {
    node: PackageNodeSection,
    p2p: PackageP2pSection,
    rpc: PackageRpcSection,
    bootstrap: PackageBootstrapSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PackageNodeSection {
    mode: Option<String>,
    data_dir: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PackageP2pSection {
    port: Option<u16>,
    advertise_addr: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PackageRpcSection {
    port: Option<u16>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PackageBootstrapSection {
    seed_file: Option<String>,
}

struct BundlePaths {
    base_dir: PathBuf,
    node_bin: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Some(LauncherCommand::Doctor(args)) => run_doctor(args),
        Some(LauncherCommand::SelfHost(args)) => run_self_host(args),
        None => run_start(&cli.start),
    }
}

fn run_start(args: &StartArgs) -> anyhow::Result<()> {
    let bundle = resolve_bundle_paths(args.node_bin.clone())?;
    let config_path = args.config.clone().unwrap_or_else(|| {
        bundle
            .base_dir
            .join("config")
            .join(profile_config_name(&args.profile))
    });

    ensure_start_paths(&bundle.node_bin, &config_path)?;

    env::set_current_dir(&bundle.base_dir)
        .with_context(|| format!("failed to switch into '{}'", bundle.base_dir.display()))?;

    println!("MISAKA launcher");
    println!("  profile : {}", profile_label(&args.profile));
    println!("  binary  : {}", bundle.node_bin.display());
    println!("  config  : {}", config_path.display());
    println!();

    let status = Command::new(&bundle.node_bin)
        .arg("--config")
        .arg(&config_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("failed to start '{}'", bundle.node_bin.display()))?;

    handle_exit(status)
}

fn run_doctor(args: &DoctorArgs) -> anyhow::Result<()> {
    let bundle = resolve_bundle_paths(None)?;
    let config_path = args.config.clone().unwrap_or_else(|| {
        bundle
            .base_dir
            .join("config")
            .join(profile_config_name(&args.profile))
    });
    if !config_path.exists() {
        return exit_with_pause(anyhow!("config file not found: {}", config_path.display()));
    }

    let cfg = load_package_config(&config_path)?;
    let config_dir = config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| bundle.base_dir.join("config"));
    let p2p_port = cfg.p2p.port.unwrap_or(default_p2p_port(&args.profile));
    let rpc_port = cfg.rpc.port.unwrap_or(default_rpc_port(&args.profile));
    let seed_file = cfg
        .bootstrap
        .seed_file
        .as_deref()
        .map(|raw| resolve_relative_path(&config_dir, raw));
    let seeds = seed_file
        .as_deref()
        .map(read_seed_lines)
        .transpose()
        .unwrap_or_default()
        .unwrap_or_default();
    let outbound_ip = detect_local_ip().map(|ip| ip.to_string());

    println!("MISAKA network doctor");
    println!("  profile        : {}", profile_label(&args.profile));
    println!("  config         : {}", config_path.display());
    println!("  package dir    : {}", bundle.base_dir.display());
    println!(
        "  mode           : {}",
        cfg.node.mode.as_deref().unwrap_or("unknown")
    );
    println!("  p2p port       : {p2p_port}");
    println!("  rpc port       : {rpc_port}");
    println!(
        "  advertise addr : {}",
        cfg.p2p.advertise_addr.as_deref().unwrap_or("not set")
    );
    println!(
        "  data dir       : {}",
        cfg.node.data_dir.as_deref().unwrap_or("not set")
    );
    println!();

    println!("Port checks");
    println!("  TCP {p2p_port}: {}", port_status_text(p2p_port));
    println!("  TCP {rpc_port}: {}", port_status_text(rpc_port));
    println!();

    println!("Bootstrap");
    if let Some(path) = &seed_file {
        println!("  seed file      : {}", path.display());
    } else {
        println!("  seed file      : not set");
    }
    if seeds.is_empty() {
        println!("  published seeds: none");
    } else {
        println!("  published seeds:");
        for seed in &seeds {
            println!("    - {seed}");
        }
    }
    println!();

    println!("LAN hint");
    match outbound_ip {
        Some(ip) => println!("  current LAN IP : {ip}"),
        None => println!("  current LAN IP : could not detect automatically"),
    }
    println!();

    println!("What to do");
    match args.profile {
        LauncherProfile::Public => {
            println!("  - 参加だけなら router のポート開放は必須ではありません。live な seed へ outbound 接続できれば動きます。");
            println!("  - 他ノードから見える public node にしたいなら TCP {p2p_port} をこのPCへ転送して advertise_addr を設定してください。");
            println!("  - 公式 seed が止まっている間は `misaka-launcher self-host` で手元 seed に接続できます。");
        }
        LauncherProfile::Seed => {
            println!(
                "  - seed を他人に使ってもらうには TCP {p2p_port} をこのPCへ転送してください。"
            );
            println!("  - RPC {rpc_port} は通常ローカル確認用なので router 側で公開する必要はありません。");
            println!("  - `misaka-launcher self-host` でも同じ seed profile を使ってローカル検証できます。");
        }
        LauncherProfile::Validator => {
            println!("  - validator として外部参加するなら TCP {p2p_port} の転送と advertise_addr の設定が必要です。");
            println!("  - seed 停止中の切り分け用には `misaka-launcher self-host` でまずローカル接続確認をしてください。");
        }
    }

    Ok(())
}

fn run_self_host(args: &SelfHostArgs) -> anyhow::Result<()> {
    let bundle = resolve_bundle_paths(args.node_bin.clone())?;
    let default_config_dir = bundle.base_dir.join("config");
    let seed_config = args
        .seed_config
        .clone()
        .unwrap_or_else(|| default_config_dir.join(profile_config_name(&LauncherProfile::Seed)));
    let public_config = args
        .public_config
        .clone()
        .unwrap_or_else(|| default_config_dir.join(profile_config_name(&LauncherProfile::Public)));
    let seed_seed_file = companion_config_path(
        seed_config.parent(),
        &default_config_dir,
        "offline-seeds.txt",
    );
    let public_seed_file = companion_config_path(
        public_config.parent(),
        &default_config_dir,
        "self-host-seeds.txt",
    );
    let logs_dir = bundle.base_dir.join("logs");
    let seed_log_path = logs_dir.join("self-host-seed.log");

    ensure_start_paths(&bundle.node_bin, &seed_config)?;
    ensure_start_paths(&bundle.node_bin, &public_config)?;
    ensure_exists(&seed_seed_file, "self-host seed file")?;
    ensure_exists(&public_seed_file, "public self-host seed file")?;
    fs::create_dir_all(&logs_dir)
        .with_context(|| format!("failed to create '{}'", logs_dir.display()))?;

    env::set_current_dir(&bundle.base_dir)
        .with_context(|| format!("failed to switch into '{}'", bundle.base_dir.display()))?;

    println!("MISAKA self-host");
    println!("  node binary : {}", bundle.node_bin.display());
    println!("  seed config : {}", seed_config.display());
    println!("  public cfg  : {}", public_config.display());
    println!("  seed log    : {}", seed_log_path.display());
    println!("  seed addr   : {}", args.seed_addr);
    println!();

    let mut seed_child = spawn_seed_child(
        &bundle.node_bin,
        &seed_config,
        &seed_seed_file,
        &seed_log_path,
    )?;
    println!("Started local seed (pid={})", seed_child.id());
    println!("Waiting {DEFAULT_STARTUP_WAIT_SECS}s for the seed to come up...");
    thread::sleep(Duration::from_secs(DEFAULT_STARTUP_WAIT_SECS));

    if let Some(status) = seed_child.try_wait()? {
        return exit_with_pause(anyhow!(
            "local seed exited early with status {}. Check {}",
            status,
            seed_log_path.display()
        ));
    }

    println!("Starting public node attached to local seed...");
    println!();

    let status = Command::new(&bundle.node_bin)
        .arg("--config")
        .arg(&public_config)
        .env("MISAKA_NODE_SEED_FILE", &public_seed_file)
        .env("MISAKA_NODE_SEEDS", &args.seed_addr)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("failed to start '{}'", bundle.node_bin.display()))?;

    terminate_child(&mut seed_child);
    handle_exit(status)
}

fn spawn_seed_child(
    node_bin: &Path,
    seed_config: &Path,
    seed_seed_file: &Path,
    log_path: &Path,
) -> anyhow::Result<Child> {
    let log_file = File::create(log_path)
        .with_context(|| format!("failed to create '{}'", log_path.display()))?;
    let err_file = log_file
        .try_clone()
        .with_context(|| format!("failed to clone '{}'", log_path.display()))?;

    Command::new(node_bin)
        .arg("--config")
        .arg(seed_config)
        .env("MISAKA_NODE_SEED_FILE", seed_seed_file)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(err_file))
        .spawn()
        .with_context(|| format!("failed to spawn '{}'", node_bin.display()))
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn handle_exit(status: ExitStatus) -> anyhow::Result<()> {
    if status.success() {
        Ok(())
    } else {
        exit_with_pause(anyhow!("misaka-node exited with status {}", status))
    }
}

fn exit_with_pause(error: anyhow::Error) -> anyhow::Result<()> {
    eprintln!("ERROR: {error}");
    eprintln!("Press Enter to exit...");
    let mut buf = [0u8; 1];
    let _ = io::stdin().read(&mut buf).ok();
    bail!(error)
}

fn resolve_bundle_paths(node_bin_override: Option<PathBuf>) -> anyhow::Result<BundlePaths> {
    let exe_path = env::current_exe().context("failed to resolve launcher path")?;
    let base_dir = exe_path
        .parent()
        .map(Path::to_path_buf)
        .context("launcher has no parent directory")?;
    let node_bin = node_bin_override.unwrap_or_else(|| base_dir.join(binary_name("misaka-node")));
    Ok(BundlePaths { base_dir, node_bin })
}

fn ensure_start_paths(node_bin: &Path, config_path: &Path) -> anyhow::Result<()> {
    ensure_exists(node_bin, "misaka-node binary")?;
    ensure_exists(config_path, "config file")?;
    Ok(())
}

fn ensure_exists(path: &Path, label: &str) -> anyhow::Result<()> {
    if path.exists() {
        Ok(())
    } else {
        Err(anyhow!("{label} not found: {}", path.display()))
    }
}

fn load_package_config(path: &Path) -> anyhow::Result<PackageConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file '{}'", path.display()))?;
    toml::from_str::<PackageConfig>(&raw)
        .with_context(|| format!("failed to parse config file '{}'", path.display()))
}

fn read_seed_lines(path: &Path) -> anyhow::Result<Vec<String>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read seed file '{}'", path.display()))?;
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect())
}

fn resolve_relative_path(base_dir: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

fn companion_config_path(
    selected_config_dir: Option<&Path>,
    default_config_dir: &Path,
    file_name: &str,
) -> PathBuf {
    selected_config_dir
        .map(|dir| dir.join(file_name))
        .filter(|path| path.exists())
        .unwrap_or_else(|| default_config_dir.join(file_name))
}

fn port_status_text(port: u16) -> String {
    match TcpListener::bind(("0.0.0.0", port)) {
        Ok(listener) => {
            drop(listener);
            "available".to_string()
        }
        Err(err) => format!("already in use or blocked ({err})"),
    }
}

fn detect_local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
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

fn default_p2p_port(profile: &LauncherProfile) -> u16 {
    match profile {
        LauncherProfile::Public => 6691,
        LauncherProfile::Seed => 6690,
        LauncherProfile::Validator => 6692,
    }
}

fn default_rpc_port(profile: &LauncherProfile) -> u16 {
    match profile {
        LauncherProfile::Public => 3001,
        LauncherProfile::Seed => 3011,
        LauncherProfile::Validator => 3003,
    }
}
