use anyhow::Context;
use clap::{parser::ValueSource, ArgMatches};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

use super::Cli;

const DEFAULT_TESTNET_GENESIS_TIMESTAMP_MS: u64 = 1_773_446_400_000; // 2026-03-14T00:00:00Z
const DEFAULT_MAINNET_GENESIS_TIMESTAMP_MS: u64 = 1_767_225_600_000; // 2026-01-01T00:00:00Z
const DEFAULT_SEED_REFRESH_SECS: u64 = 30;

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub config_path: Option<PathBuf>,
    pub seed_file: Option<PathBuf>,
    pub seed_refresh_secs: u64,
    pub genesis_timestamp_ms: u64,
}

impl RuntimeConfig {
    pub fn load_dynamic_seed_nodes(&self) -> anyhow::Result<Vec<String>> {
        match &self.seed_file {
            Some(path) => read_seed_file(path),
            None => Ok(Vec::new()),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FileConfig {
    chain: ChainSection,
    node: NodeSection,
    p2p: P2pSection,
    rpc: RpcSection,
    consensus: ConsensusSection,
    faucet: FaucetSection,
    bootstrap: BootstrapSection,
    genesis: GenesisSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ChainSection {
    chain_id: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct NodeSection {
    name: Option<String>,
    mode: Option<String>,
    data_dir: Option<String>,
    log_level: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct P2pSection {
    port: Option<u16>,
    advertise_addr: Option<String>,
    max_inbound_peers: Option<usize>,
    max_outbound_peers: Option<usize>,
    outbound_only: Option<bool>,
    hide_my_ip: Option<bool>,
    proxy: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RpcSection {
    port: Option<u16>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ConsensusSection {
    block_time_secs: Option<u64>,
    validator: Option<bool>,
    validator_index: Option<usize>,
    validators: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FaucetSection {
    enabled: Option<bool>,
    amount: Option<u64>,
    cooldown_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BootstrapSection {
    seed_nodes: Vec<String>,
    static_peers: Vec<String>,
    seed_file: Option<String>,
    reconnect_interval_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct GenesisSection {
    timestamp_ms: Option<u64>,
}

pub(crate) fn resolve_runtime_config(
    matches: &ArgMatches,
    cli: &mut Cli,
) -> anyhow::Result<RuntimeConfig> {
    let config_path = resolve_config_path(matches, cli);
    let file_config = match &config_path {
        Some(path) => Some(load_file_config(path)?),
        None => None,
    };
    let config_dir = config_path
        .as_deref()
        .and_then(Path::parent)
        .map(Path::to_path_buf);

    if let Some(cfg) = file_config.as_ref() {
        apply_file_config(matches, cli, cfg, config_dir.as_deref());
    }
    apply_env_overrides(matches, cli);

    let seed_file = resolve_seed_file(&file_config, config_dir.as_deref());
    if let Some(path) = &seed_file {
        let extra = read_seed_file(path)?;
        merge_unique(&mut cli.seeds, extra);
    }

    let seed_refresh_secs = resolve_seed_refresh_secs(&file_config);
    let genesis_timestamp_ms = resolve_genesis_timestamp_ms(&file_config, cli.chain_id);

    Ok(RuntimeConfig {
        config_path,
        seed_file,
        seed_refresh_secs,
        genesis_timestamp_ms,
    })
}

pub fn default_genesis_timestamp_ms(chain_id: u32) -> u64 {
    match chain_id {
        1 => DEFAULT_MAINNET_GENESIS_TIMESTAMP_MS,
        _ => DEFAULT_TESTNET_GENESIS_TIMESTAMP_MS,
    }
}

pub fn read_seed_file(path: &Path) -> anyhow::Result<Vec<String>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read seed file '{}'", path.display()))?;
    let mut seeds = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        seeds.push(trimmed.to_string());
    }
    Ok(seeds)
}

fn resolve_config_path(matches: &ArgMatches, cli: &Cli) -> Option<PathBuf> {
    if is_cli_explicit(matches, "config") {
        return cli.config.as_ref().map(PathBuf::from);
    }
    std::env::var_os("MISAKA_NODE_CONFIG")
        .map(PathBuf::from)
        .or_else(|| cli.config.as_ref().map(PathBuf::from))
}

fn load_file_config(path: &Path) -> anyhow::Result<FileConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file '{}'", path.display()))?;
    toml::from_str::<FileConfig>(&raw)
        .with_context(|| format!("failed to parse config file '{}'", path.display()))
}

fn apply_file_config(matches: &ArgMatches, cli: &mut Cli, cfg: &FileConfig, config_dir: Option<&Path>) {
    apply_if_not_cli(matches, "name", &mut cli.name, cfg.node.name.clone());
    apply_if_not_cli(matches, "mode", &mut cli.mode, cfg.node.mode.clone());
    apply_if_not_cli(
        matches,
        "data_dir",
        &mut cli.data_dir,
        cfg.node
            .data_dir
            .as_deref()
            .map(|v| resolve_path_string(config_dir, v)),
    );
    apply_if_not_cli(matches, "log_level", &mut cli.log_level, cfg.node.log_level.clone());
    apply_if_not_cli(matches, "chain_id", &mut cli.chain_id, cfg.chain.chain_id);
    apply_if_not_cli(matches, "p2p_port", &mut cli.p2p_port, cfg.p2p.port);
    apply_if_not_cli(matches, "rpc_port", &mut cli.rpc_port, cfg.rpc.port);
    apply_if_not_cli(
        matches,
        "block_time",
        &mut cli.block_time,
        cfg.consensus.block_time_secs,
    );
    apply_if_not_cli(
        matches,
        "validator_index",
        &mut cli.validator_index,
        cfg.consensus.validator_index,
    );
    apply_if_not_cli(matches, "validators", &mut cli.validators, cfg.consensus.validators);
    apply_if_not_cli(matches, "validator", &mut cli.validator, cfg.consensus.validator);
    apply_if_not_cli(
        matches,
        "advertise_addr",
        &mut cli.advertise_addr,
        Some(cfg.p2p.advertise_addr.clone()),
    );
    apply_if_not_cli(
        matches,
        "max_inbound_peers",
        &mut cli.max_inbound_peers,
        Some(cfg.p2p.max_inbound_peers),
    );
    apply_if_not_cli(
        matches,
        "max_outbound_peers",
        &mut cli.max_outbound_peers,
        Some(cfg.p2p.max_outbound_peers),
    );
    apply_if_not_cli(
        matches,
        "outbound_only",
        &mut cli.outbound_only,
        cfg.p2p.outbound_only,
    );
    apply_if_not_cli(matches, "hide_my_ip", &mut cli.hide_my_ip, cfg.p2p.hide_my_ip);
    apply_if_not_cli(matches, "proxy", &mut cli.proxy, Some(cfg.p2p.proxy.clone()));
    apply_if_not_cli(
        matches,
        "faucet_amount",
        &mut cli.faucet_amount,
        cfg.faucet.amount.or_else(|| {
            cfg.faucet
                .enabled
                .and_then(|enabled| if enabled { None } else { Some(0) })
        }),
    );
    apply_if_not_cli(
        matches,
        "faucet_cooldown_ms",
        &mut cli.faucet_cooldown_ms,
        cfg.faucet.cooldown_secs.map(|secs| secs.saturating_mul(1000)),
    );

    if !is_cli_explicit(matches, "peers") && !cfg.bootstrap.static_peers.is_empty() {
        cli.peers = cfg.bootstrap.static_peers.clone();
    }
    if !is_cli_explicit(matches, "seeds") && !cfg.bootstrap.seed_nodes.is_empty() {
        cli.seeds = cfg.bootstrap.seed_nodes.clone();
    }
}

fn apply_env_overrides(matches: &ArgMatches, cli: &mut Cli) {
    apply_env_string(matches, "name", &mut cli.name, "MISAKA_NODE_NAME");
    apply_env_string(matches, "mode", &mut cli.mode, "MISAKA_NODE_MODE");
    apply_env_string(matches, "data_dir", &mut cli.data_dir, "MISAKA_NODE_DATA_DIR");
    apply_env_string(matches, "log_level", &mut cli.log_level, "MISAKA_NODE_LOG_LEVEL");
    apply_env_parsed(matches, "chain_id", &mut cli.chain_id, "MISAKA_NODE_CHAIN_ID");
    apply_env_parsed(matches, "rpc_port", &mut cli.rpc_port, "MISAKA_NODE_RPC_PORT");
    apply_env_parsed(matches, "p2p_port", &mut cli.p2p_port, "MISAKA_NODE_P2P_PORT");
    apply_env_parsed(
        matches,
        "block_time",
        &mut cli.block_time,
        "MISAKA_NODE_BLOCK_TIME_SECS",
    );
    apply_env_parsed(
        matches,
        "validator_index",
        &mut cli.validator_index,
        "MISAKA_NODE_VALIDATOR_INDEX",
    );
    apply_env_parsed(
        matches,
        "validators",
        &mut cli.validators,
        "MISAKA_NODE_VALIDATOR_COUNT",
    );
    apply_env_bool(matches, "validator", &mut cli.validator, "MISAKA_NODE_VALIDATOR");
    apply_env_string_option(
        matches,
        "advertise_addr",
        &mut cli.advertise_addr,
        "MISAKA_NODE_ADVERTISE_ADDR",
    );
    apply_env_parsed_option(
        matches,
        "max_inbound_peers",
        &mut cli.max_inbound_peers,
        "MISAKA_NODE_MAX_INBOUND_PEERS",
    );
    apply_env_parsed_option(
        matches,
        "max_outbound_peers",
        &mut cli.max_outbound_peers,
        "MISAKA_NODE_MAX_OUTBOUND_PEERS",
    );
    apply_env_bool(
        matches,
        "outbound_only",
        &mut cli.outbound_only,
        "MISAKA_NODE_OUTBOUND_ONLY",
    );
    apply_env_bool(
        matches,
        "hide_my_ip",
        &mut cli.hide_my_ip,
        "MISAKA_NODE_HIDE_MY_IP",
    );
    apply_env_string_option(matches, "proxy", &mut cli.proxy, "MISAKA_NODE_PROXY");
    apply_env_parsed(
        matches,
        "faucet_amount",
        &mut cli.faucet_amount,
        "MISAKA_NODE_FAUCET_AMOUNT",
    );
    apply_env_parsed(
        matches,
        "faucet_cooldown_ms",
        &mut cli.faucet_cooldown_ms,
        "MISAKA_NODE_FAUCET_COOLDOWN_MS",
    );

    if !is_cli_explicit(matches, "peers") {
        if let Some(raw) = get_env("MISAKA_NODE_PEERS") {
            cli.peers = split_csv(&raw);
        }
    }
    if !is_cli_explicit(matches, "seeds") {
        if let Some(raw) = get_env("MISAKA_NODE_SEEDS") {
            cli.seeds = split_csv(&raw);
        }
    }
}

fn resolve_seed_file(file_config: &Option<FileConfig>, config_dir: Option<&Path>) -> Option<PathBuf> {
    std::env::var_os("MISAKA_NODE_SEED_FILE")
        .map(PathBuf::from)
        .or_else(|| {
            file_config
                .as_ref()
                .and_then(|cfg| cfg.bootstrap.seed_file.as_ref().map(PathBuf::from))
        })
        .map(|path| resolve_path(config_dir, &path))
}

fn resolve_seed_refresh_secs(file_config: &Option<FileConfig>) -> u64 {
    std::env::var("MISAKA_NODE_SEED_REFRESH_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .or_else(|| {
            file_config
                .as_ref()
                .and_then(|cfg| cfg.bootstrap.reconnect_interval_secs)
        })
        .unwrap_or(DEFAULT_SEED_REFRESH_SECS)
        .max(5)
}

fn resolve_genesis_timestamp_ms(file_config: &Option<FileConfig>, chain_id: u32) -> u64 {
    std::env::var("MISAKA_GENESIS_TIMESTAMP_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .or_else(|| {
            file_config
                .as_ref()
                .and_then(|cfg| cfg.genesis.timestamp_ms)
        })
        .unwrap_or_else(|| default_genesis_timestamp_ms(chain_id))
}

fn resolve_path(config_dir: Option<&Path>, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else if let Some(base) = config_dir {
        base.join(path)
    } else {
        path.to_path_buf()
    }
}

fn resolve_path_string(config_dir: Option<&Path>, path: &str) -> String {
    resolve_path(config_dir, Path::new(path))
        .to_string_lossy()
        .into_owned()
}

fn apply_if_not_cli<T>(matches: &ArgMatches, id: &str, target: &mut T, value: Option<T>) {
    if !is_cli_explicit(matches, id) {
        if let Some(value) = value {
            *target = value;
        }
    }
}

fn is_cli_explicit(matches: &ArgMatches, id: &str) -> bool {
    matches.value_source(id) == Some(ValueSource::CommandLine)
}

fn apply_env_string(matches: &ArgMatches, id: &str, target: &mut String, env_name: &str) {
    if !is_cli_explicit(matches, id) {
        if let Some(value) = get_env(env_name) {
            *target = value;
        }
    }
}

fn apply_env_string_option(
    matches: &ArgMatches,
    id: &str,
    target: &mut Option<String>,
    env_name: &str,
) {
    if !is_cli_explicit(matches, id) {
        if let Some(value) = get_env(env_name) {
            *target = Some(value);
        }
    }
}

fn apply_env_bool(matches: &ArgMatches, id: &str, target: &mut bool, env_name: &str) {
    if !is_cli_explicit(matches, id) {
        if let Some(value) = get_env(env_name).and_then(|raw| parse_bool(&raw)) {
            *target = value;
        }
    }
}

fn apply_env_parsed<T>(matches: &ArgMatches, id: &str, target: &mut T, env_name: &str)
where
    T: std::str::FromStr,
{
    if !is_cli_explicit(matches, id) {
        if let Some(value) = get_env(env_name).and_then(|raw| raw.parse::<T>().ok()) {
            *target = value;
        }
    }
}

fn apply_env_parsed_option<T>(
    matches: &ArgMatches,
    id: &str,
    target: &mut Option<T>,
    env_name: &str,
) where
    T: std::str::FromStr,
{
    if !is_cli_explicit(matches, id) {
        if let Some(value) = get_env(env_name).and_then(|raw| raw.parse::<T>().ok()) {
            *target = Some(value);
        }
    }
}

fn get_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
}

fn parse_bool(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn merge_unique(target: &mut Vec<String>, values: Vec<String>) {
    for value in values {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_seed_file_skips_comments_and_blanks() {
        let temp_dir = std::env::temp_dir().join(format!(
            "misaka-seeds-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let seed_path = temp_dir.join("seeds.txt");
        fs::write(
            &seed_path,
            "# comment\n\n49.212.136.189:6690\n 127.0.0.1:6690 \n",
        )
        .unwrap();

        let seeds = read_seed_file(&seed_path).unwrap();
        assert_eq!(seeds, vec!["49.212.136.189:6690", "127.0.0.1:6690"]);

        fs::remove_file(seed_path).unwrap();
        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn test_file_config_parses_bootstrap_sections() {
        let raw = r#"
[node]
name = "public-01"

[bootstrap]
seed_nodes = ["49.212.136.189:6690"]
seed_file = "./config/seeds.txt"
reconnect_interval_secs = 45

[genesis]
timestamp_ms = 1773446400000
"#;

        let parsed: FileConfig = toml::from_str(raw).unwrap();
        assert_eq!(parsed.node.name.as_deref(), Some("public-01"));
        assert_eq!(parsed.bootstrap.seed_nodes, vec!["49.212.136.189:6690"]);
        assert_eq!(
            parsed.bootstrap.seed_file.as_deref(),
            Some("./config/seeds.txt")
        );
        assert_eq!(parsed.bootstrap.reconnect_interval_secs, Some(45));
        assert_eq!(parsed.genesis.timestamp_ms, Some(1_773_446_400_000));
    }

    #[test]
    fn test_default_genesis_timestamp_is_stable() {
        assert_eq!(default_genesis_timestamp_ms(2), 1_773_446_400_000);
        assert_eq!(default_genesis_timestamp_ms(1), 1_767_225_600_000);
    }
}
