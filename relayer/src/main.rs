//! MISAKA Bridge Relayer — Burn & Mint Model
//!
//! Flow:
//! 1. Users burn SPL tokens on Solana (real SPL Token Burn instruction)
//! 2. Relayer detects burns by polling via BurnEventSource
//! 3. Burns are verified on-chain via BurnVerifier
//! 4. Verified burns are attested (N-of-M via AttestationCollector)
//! 5. Authorized burns are minted on MISAKA chain via MintExecutor
//! 6. Status is tracked in SQLite with full audit logging

use std::sync::Arc;
use tokio::time::{Duration, interval};
use tracing::{error, info, warn};

mod api;
mod attestation;
mod burn_source;
mod burn_verifier;
mod config;
pub mod error;
mod message;
mod mint_executor;
mod misaka_watcher;
mod solana_watcher;
mod store;

use attestation::{AttestationCollector, AttestationConfig};
use burn_source::{BurnEventSource, SolanaRpcBurnSource};
use burn_verifier::BurnVerifier;
use config::{BurnSourceKind, MintExecutorKind, RelayerConfig};
use mint_executor::{MintExecutor, MintRequest, MisakaRpcMintExecutor, MockMintExecutor};
use store::{BurnRequestStore, ClaimResult};

/// Load relayer public keys from the RELAYER_PUBKEYS_DIR directory.
///
/// Each file in the directory should contain a hex-encoded ML-DSA-65 public key
/// (1952 bytes = 3904 hex chars). In single-relayer mode (attestation_total=1),
/// the relayer's own key is loaded from the keypair file.
///
/// Falls back to generating deterministic placeholder keys ONLY in devnet/testnet
/// for development convenience. Mainnet requires real keys.
fn load_relayer_pubkeys(config: &RelayerConfig) -> anyhow::Result<Vec<Vec<u8>>> {
    // Try to load from RELAYER_PUBKEYS env (comma-separated hex keys)
    if let Ok(keys_str) = std::env::var("RELAYER_PUBKEYS") {
        let keys: Vec<Vec<u8>> = keys_str
            .split(',')
            .map(|s| hex::decode(s.trim()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("RELAYER_PUBKEYS: invalid hex: {}", e))?;
        if keys.len() != config.attestation_total {
            anyhow::bail!(
                "RELAYER_PUBKEYS has {} keys but ATTESTATION_TOTAL={}",
                keys.len(),
                config.attestation_total
            );
        }
        for (i, k) in keys.iter().enumerate() {
            if k.len() != 1952 {
                anyhow::bail!(
                    "RELAYER_PUBKEYS[{}]: expected 1952 bytes (ML-DSA-65), got {}",
                    i,
                    k.len()
                );
            }
        }
        return Ok(keys);
    }

    // Mainnet: RELAYER_PUBKEYS is mandatory
    if config.network == config::NetworkMode::Mainnet {
        anyhow::bail!(
            "FATAL: RELAYER_PUBKEYS env is required on mainnet. \
             Provide comma-separated hex-encoded ML-DSA-65 public keys (1952 bytes each)."
        );
    }

    // Devnet/Testnet fallback: generate deterministic placeholder keys
    // These are NOT cryptographically valid — only used for development
    warn!(
        "Using placeholder relayer keys (devnet/testnet only). \
         Set RELAYER_PUBKEYS for production."
    );
    Ok((0..config.attestation_total)
        .map(|i| {
            let mut key = vec![0u8; 1952];
            // Fill with deterministic non-zero pattern
            for (j, byte) in key.iter_mut().enumerate() {
                *byte = ((i as u8).wrapping_add(1)).wrapping_mul((j as u8).wrapping_add(1));
            }
            key
        })
        .collect())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = match RelayerConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!("{}", e);
            std::process::exit(1);
        }
    };

    let store_path = config.processed_store_path.with_extension("db");
    let store = Arc::new(BurnRequestStore::open(&store_path)?);
    let verifier = Arc::new(BurnVerifier::new(config.clone()));

    // ── Build BurnEventSource based on config ──
    let burn_source: Box<dyn BurnEventSource> = match config.burn_source {
        BurnSourceKind::SolanaRpc => {
            Box::new(SolanaRpcBurnSource::new(config.clone()))
        }
    };

    // ── Startup safety check: reject MisakaRpc executor on mainnet ──
    // The bridge mint RPC endpoint does not exist yet. Using MisakaRpc on
    // mainnet would silently fail or produce undefined behavior.
    if config.network == config::NetworkMode::Mainnet
        && config.mint_executor == MintExecutorKind::MisakaRpc
    {
        error!(
            "FATAL: bridge mint endpoint not implemented \u2014 cannot use MisakaRpc executor on mainnet. \
             Set MINT_EXECUTOR_KIND=mock or deploy the mint endpoint first."
        );
        std::process::exit(1);
    }

    // ── Build MintExecutor based on config ──
    let mint_executor: Box<dyn MintExecutor> = match config.mint_executor {
        MintExecutorKind::MisakaRpc => {
            Box::new(MisakaRpcMintExecutor::new(config.clone()))
        }
        MintExecutorKind::Mock => {
            Box::new(MockMintExecutor)
        }
    };

    // ── Build AttestationCollector ──
    // In single-relayer mode (N=1, M=1), attestation is automatic.
    let authorized_relayers = load_relayer_pubkeys(&config)?;
    let app_id = misaka_types::intent::AppId::new(config.misaka_chain_id, config.genesis_hash);
    let mut attestation_collector = AttestationCollector::new(AttestationConfig {
        required_signatures: config.attestation_required,
        total_relayers: config.attestation_total,
        authorized_relayers,
        // SEC-FIX: own_index must be unique per relayer instance in multi-relayer setups.
        // Previously hardcoded to 0, causing all instances to report as "relayer 0"
        // and breaking N-of-M attestation quorum (only 1 unique relayer counted).
        own_index: std::env::var("RELAYER_OWN_INDEX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0),
        app_id,
    });

    info!("MISAKA Bridge Relayer (Burn & Mint) starting");
    info!("Network mode: {:?}", config.network);
    info!("Solana RPC: {}", config.solana_rpc_url);
    info!("Misaka RPC: {}", config.misaka_rpc_url);
    info!("MISAKA Mint: {}", config.solana_misaka_mint);
    info!("API port: {}", config.api_port);
    info!("Poll interval: {}s", config.poll_interval_secs);
    info!("Store: {}", store_path.display());
    info!("Burn source: {:?}", config.burn_source);
    info!("Mint executor: {}", mint_executor.name());
    info!(
        "Attestation: {}-of-{} relayers",
        config.attestation_required, config.attestation_total
    );

    // ── Start API server in background ──
    let api_state = Arc::new(api::ApiState {
        store: Arc::clone(&store),
        verifier: Arc::clone(&verifier),
        config: config.clone(),
    });
    tokio::spawn(api::run_api_server(api_state));

    // ── Main event loop ──
    let mut ticker = interval(Duration::from_secs(config.poll_interval_secs));
    let mut bridge_paused = false;

    // Load persisted cursor for burn polling
    let mut last_burn_cursor: Option<String> = store.get_cursor("burn_cursor").unwrap_or(None);
    if let Some(ref cursor) = last_burn_cursor {
        info!(
            "Resuming burn poll from cursor: {}...",
            &cursor[..16.min(cursor.len())]
        );
    }

    loop {
        ticker.tick().await;

        // ── Circuit breaker ──
        if bridge_paused {
            warn!("Bridge is PAUSED (circuit breaker). Set MISAKA_BRIDGE_RESUME=1 to resume.");
            if std::env::var("MISAKA_BRIDGE_RESUME").ok().as_deref() == Some("1") {
                info!("Bridge resumed by operator (MISAKA_BRIDGE_RESUME=1)");
                std::env::remove_var("MISAKA_BRIDGE_RESUME");
                bridge_paused = false;
            }
            continue;
        }

        // ══════════════════════════════════════════════════════
        //  Phase 1: Poll for new burn events via BurnEventSource
        // ══════════════════════════════════════════════════════
        match burn_source.poll_burns(last_burn_cursor.as_deref()).await {
            Ok((events, new_cursor)) => {
                // Persist cursor before processing
                if let Some(ref cursor) = new_cursor {
                    if last_burn_cursor.as_deref() != Some(cursor.as_str()) {
                        if let Err(e) = store.set_cursor("burn_cursor", cursor) {
                            warn!("Failed to persist burn cursor: {}", e);
                        }
                    }
                }
                last_burn_cursor = new_cursor;

                for event in events {
                    // Check if address is registered
                    let misaka_addr = match store.get_registered_address(&event.wallet_address) {
                        Ok(Some(addr)) => addr,
                        Ok(None) => {
                            info!(
                                "[BURN] No registered address for wallet {}, skipping tx {}",
                                &event.wallet_address[..16.min(event.wallet_address.len())],
                                &event.solana_tx_signature[..16.min(event.solana_tx_signature.len())]
                            );
                            continue;
                        }
                        Err(e) => {
                            warn!("Store error looking up address: {}", e);
                            continue;
                        }
                    };

                    // Verify the burn with BurnVerifier
                    match verifier
                        .verify_burn_tx(
                            &event.solana_tx_signature,
                            &event.wallet_address,
                        )
                        .await
                    {
                        Ok(verified) => {
                            // Insert as verified
                            match store.insert_burn_request(
                                &event.id,
                                &event.wallet_address,
                                &misaka_addr,
                                &event.mint_address,
                                event.burn_amount_raw,
                                &event.solana_tx_signature,
                                event.slot,
                                event.block_time,
                                "verified",
                            ) {
                                Ok(true) => {
                                    let _ = store.audit_log(
                                        "burn_detected_and_verified",
                                        Some(&event.id),
                                        &format!(
                                            "tx={} amount={} wallet={} slot={}",
                                            &event.solana_tx_signature[..16.min(event.solana_tx_signature.len())],
                                            event.burn_amount_raw,
                                            &event.wallet_address[..16.min(event.wallet_address.len())],
                                            event.slot
                                        ),
                                    );
                                    info!(
                                        "[BURN] Verified: id={} amount={} wallet={}",
                                        &event.id[..16],
                                        event.burn_amount_raw,
                                        &event.wallet_address[..16.min(event.wallet_address.len())]
                                    );

                                    // ── Attestation: sign this burn ──
                                    // In single-relayer mode (N=1, M=1), this
                                    // immediately authorizes the mint.
                                    let signer = |msg: &[u8]| -> Vec<u8> {
                                        use sha3::{Digest, Sha3_256};
                                        let our_key = vec![0u8; 32]; // placeholder
                                        let mut h = Sha3_256::new();
                                        h.update(&our_key);
                                        h.update(msg);
                                        h.finalize().to_vec()
                                    };
                                    attestation_collector.attest(
                                        &verified,
                                        &event.id,
                                        &event.solana_tx_signature,
                                        &misaka_addr,
                                        &signer,
                                    );
                                }
                                Ok(false) => {
                                    // Already exists (duplicate)
                                    continue;
                                }
                                Err(e) => {
                                    warn!("[BURN] Failed to insert burn request: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                "[BURN] Verification failed for tx {}: {}",
                                &event.solana_tx_signature[..16.min(event.solana_tx_signature.len())],
                                e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("CIRCUIT BREAKER") || msg.contains("connection failed") {
                    error!("{}", msg);
                    bridge_paused = true;
                    continue;
                }
                warn!("Burn source ({}) poll error: {}", burn_source.name(), e);
            }
        }

        // ══════════════════════════════════════════════════════
        //  Phase 2: Process verified burns — submit mints
        // ══════════════════════════════════════════════════════
        let pending_burns = match store.get_burn_requests_by_status("verified") {
            Ok(burns) => burns,
            Err(e) => {
                warn!("Failed to query verified burns: {}", e);
                vec![]
            }
        };

        // Also retry previously failed burns
        let failed_burns = match store.get_burn_requests_by_status("mint_failed") {
            Ok(burns) => burns,
            Err(e) => {
                warn!("Failed to query failed burns: {}", e);
                vec![]
            }
        };

        let all_burns: Vec<_> = pending_burns.into_iter().chain(failed_burns).collect();

        for burn in all_burns {
            // Check attestation quorum before attempting mint
            if !attestation_collector.is_authorized(&burn.id) {
                // In single-relayer mode this should not happen for verified burns.
                // In multi-relayer mode, we may still be waiting for attestations.
                if config.attestation_total > 1 {
                    info!(
                        "[MINT] Waiting for attestation quorum for id={}",
                        &burn.id[..16]
                    );
                }
                continue;
            }

            // Try to claim for processing
            match store.try_claim_burn(&burn.id) {
                Ok(ClaimResult::Claimed) => {}
                Ok(ClaimResult::AlreadyCompleted) | Ok(ClaimResult::PermanentlyFailed) => continue,
                Ok(ClaimResult::InProgress) => continue,
                Err(e) => {
                    warn!("Failed to claim burn {}: {}", &burn.id[..16], e);
                    continue;
                }
            }

            // Collect attestation signatures for the mint request
            let attestation_sigs: Vec<Vec<u8>> = attestation_collector
                .get_attestations(&burn.id)
                .map(|atts| atts.iter().map(|a| a.signature.clone()).collect())
                .unwrap_or_default();

            let mint_request = MintRequest::from_burn_row(&burn, attestation_sigs);

            info!(
                "[MINT] Submitting via {}: id={} amount={} -> {}",
                mint_executor.name(),
                &burn.id[..16],
                burn.burn_amount_raw,
                &burn.misaka_receive_address
            );

            match mint_executor.execute_mint(mint_request).await {
                Ok(result) => {
                    if let Err(e) = store.mark_mint_completed(&burn.id, &result.mint_tx_id) {
                        warn!("Failed to mark mint completed: {}", e);
                    }
                    info!(
                        "[MINT] Completed: id={} tx={}",
                        &burn.id[..16],
                        &result.mint_tx_id[..16.min(result.mint_tx_id.len())]
                    );
                }
                Err(e) => {
                    if let Err(store_err) = store.mark_mint_failed(&burn.id, &e.to_string()) {
                        warn!("Failed to mark mint failed: {}", store_err);
                    }
                    warn!(
                        "[MINT] Failed for id={}: {}",
                        &burn.id[..16],
                        e
                    );
                }
            }
        }
    }
}
