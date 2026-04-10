//! # DAG P2P Transport — PQ-Encrypted TCP ↔ DagP2pEventLoop Bridge (v2)
//!
//! Bridges TCP sockets with PQ-encrypted channels to the `DagP2pEventLoop`.
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────┐
//! │                    Wire Handshake Protocol                     │
//! │                                                                │
//! │  Initiator → Responder:                                       │
//! │    ephemeral_kem_pk (1184) + id_pk_len (4) + id_pk (1952)    │
//! │                                                                │
//! │  Responder → Initiator:                                       │
//! │    ciphertext (1088) + resp_pk_len (4) + resp_pk (1952)       │
//! │    + sig_len (4) + sig (3309)                                 │
//! │                                                                │
//! │  Initiator → Responder:                                       │
//! │    sig_len (4) + sig (3309)                                   │
//! │                                                                │
//! │  ═══════ PQ-AEAD channel established ═══════                  │
//! │  All subsequent frames: len(4) + nonce(12) + ct(N) + tag(16)  │
//! └───────────────────────────────────────────────────────────────┘
//! ```

#[cfg(feature = "dag")]
use std::collections::{HashMap, HashSet};
#[cfg(feature = "dag")]
use std::net::{IpAddr, SocketAddr};
#[cfg(feature = "dag")]
use std::sync::Arc;

#[cfg(feature = "dag")]
use sha3::{Digest, Sha3_256};
#[cfg(feature = "dag")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "dag")]
use tokio::net::{TcpListener, TcpStream};
#[cfg(feature = "dag")]
use tokio::sync::{mpsc, RwLock};
#[cfg(feature = "dag")]
use tracing::{debug, error, info, warn};

#[cfg(feature = "dag")]
use misaka_crypto::validator_sig::{
    validator_sign, validator_verify, ValidatorPqPublicKey, ValidatorPqSecretKey,
    ValidatorPqSignature,
};
#[cfg(feature = "dag")]
use misaka_p2p::handshake::{responder_handle, HandshakeResult, InitiatorHandshake};
#[cfg(feature = "dag")]
use misaka_p2p::secure_transport::{
    decrypt_frame, encode_wire_frame, AeadError, DirectionalKeys, NonceCounter, FRAME_HEADER_SIZE,
    MAX_FRAME_SIZE, NONCE_SIZE, TAG_SIZE,
};
#[cfg(feature = "dag")]
use misaka_pqc::pq_kem::MlKemPublicKey;

#[cfg(feature = "dag")]
use crate::config::NodeMode;
#[cfg(feature = "dag")]
use crate::dag_p2p_network::{InboundDagEvent, OutboundDagEvent};
#[cfg(feature = "dag")]
use misaka_dag::DagNodeState;
#[cfg(feature = "dag")]
use misaka_dag::DagStore;

#[cfg(feature = "dag")]
const HANDSHAKE_TIMEOUT_SECS: u64 = 15;
#[cfg(feature = "dag")]
const READ_TIMEOUT_SECS: u64 = 120;
#[cfg(feature = "dag")]
const PEER_OUTBOUND_CAPACITY: usize = 256;
/// Warn when nonce reaches 90% of REKEY_THRESHOLD.
#[cfg(feature = "dag")]
const REKEY_WARN_AT: u64 = (misaka_p2p::secure_transport::REKEY_THRESHOLD as f64 * 0.9) as u64;
/// Peer discovery gossip interval (seconds).
#[cfg(feature = "dag")]
const DISCOVERY_GOSSIP_INTERVAL_SECS: u64 = 60;
/// Maximum outbound connections to attempt via discovery.
#[cfg(feature = "dag")]
const MAX_DISCOVERY_CONNECTIONS: usize = 8;

/// Mainnet chain id. Used to keep inbound transport guard fail-closed on mainnet
/// while still allowing local/testnet runtime proofs over loopback.
#[cfg(feature = "dag")]
const MAINNET_CHAIN_ID: u32 = 1;

// ═══════════════════════════════════════════════════════════════
//  P0-1: Per-Message Item Count Limits
// ═══════════════════════════════════════════════════════════════

/// Maximum hashes in a single GetDagBlocks / DagInventory / BlockLocator message.
/// An attacker can send a message with 100,000 hashes to trigger O(n) DAG lookups.
#[cfg(feature = "dag")]
const MAX_HASHES_PER_MESSAGE: usize = 512;

/// Maximum parents in a NewDagBlock announcement.
/// DAG blocks typically have 1-16 parents; more is suspicious.
#[cfg(feature = "dag")]
const MAX_PARENTS_PER_BLOCK: usize = 64;

/// Maximum tips in a DagHello or DagTips message.
#[cfg(feature = "dag")]
const MAX_TIPS_PER_MESSAGE: usize = 256;

/// Maximum peer records in a Peers gossip message.
#[cfg(feature = "dag")]
const MAX_PEERS_PER_GOSSIP: usize = 64;

/// Maximum JSON payload size for block data (header + txs).
/// 4MB is the wire limit; individual JSON fields should be much smaller.
#[cfg(feature = "dag")]
const MAX_BLOCK_JSON_SIZE: usize = 2 * 1024 * 1024; // 2 MB

// ═══════════════════════════════════════════════════════════════
//  P0-3: Per-Peer Message Rate Limit
// ═══════════════════════════════════════════════════════════════

/// Maximum messages per second from a single peer.
/// Beyond this, messages are dropped at the transport layer
/// before reaching the consensus event loop.
#[cfg(feature = "dag")]
const PEER_MAX_MESSAGES_PER_SEC: u32 = 512;

#[cfg(feature = "dag")]
fn peer_max_messages_per_sec() -> u32 {
    std::env::var("MISAKA_DAG_PEER_MAX_MESSAGES_PER_SEC")
        .ok()
        .and_then(|raw| raw.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(PEER_MAX_MESSAGES_PER_SEC)
}

/// P0-1: Validate message item counts before forwarding to event loop.
///
/// Returns `Some(reason)` if the message should be rejected.
/// This is a cheap O(1) check on vector lengths — no crypto, no I/O.
#[cfg(feature = "dag")]
fn validate_message_limits(msg: &misaka_dag::dag_p2p::DagP2pMessage) -> Option<String> {
    use misaka_dag::dag_p2p::DagP2pMessage;

    match msg {
        DagP2pMessage::GetDagBlocks { hashes } if hashes.len() > MAX_HASHES_PER_MESSAGE => {
            Some(format!(
                "GetDagBlocks: {} hashes (max {})",
                hashes.len(),
                MAX_HASHES_PER_MESSAGE
            ))
        }
        DagP2pMessage::DagInventory { block_hashes, .. }
            if block_hashes.len() > MAX_HASHES_PER_MESSAGE =>
        {
            Some(format!(
                "DagInventory: {} hashes (max {})",
                block_hashes.len(),
                MAX_HASHES_PER_MESSAGE
            ))
        }
        DagP2pMessage::BlockLocator { hashes, .. } if hashes.len() > MAX_HASHES_PER_MESSAGE => {
            Some(format!(
                "BlockLocator: {} hashes (max {})",
                hashes.len(),
                MAX_HASHES_PER_MESSAGE
            ))
        }
        DagP2pMessage::DagHello {
            tips, node_name, ..
        } => {
            if tips.len() > MAX_TIPS_PER_MESSAGE {
                return Some(format!(
                    "DagHello: {} tips (max {})",
                    tips.len(),
                    MAX_TIPS_PER_MESSAGE
                ));
            }
            // Reject excessively long node names (potential log injection / memory waste)
            if node_name.len() > 256 {
                return Some(format!(
                    "DagHello: node_name {} bytes (max 256)",
                    node_name.len()
                ));
            }
            None
        }
        DagP2pMessage::DagTips { tips, .. } if tips.len() > MAX_TIPS_PER_MESSAGE => Some(format!(
            "DagTips: {} tips (max {})",
            tips.len(),
            MAX_TIPS_PER_MESSAGE
        )),
        DagP2pMessage::NewDagBlock { parents, .. } if parents.len() > MAX_PARENTS_PER_BLOCK => {
            Some(format!(
                "NewDagBlock: {} parents (max {})",
                parents.len(),
                MAX_PARENTS_PER_BLOCK
            ))
        }
        DagP2pMessage::Peers { peers } if peers.len() > MAX_PEERS_PER_GOSSIP => Some(format!(
            "Peers: {} entries (max {})",
            peers.len(),
            MAX_PEERS_PER_GOSSIP
        )),
        DagP2pMessage::GetBodies { hashes } if hashes.len() > MAX_HASHES_PER_MESSAGE => {
            Some(format!(
                "GetBodies: {} hashes (max {})",
                hashes.len(),
                MAX_HASHES_PER_MESSAGE
            ))
        }
        DagP2pMessage::Bodies { blocks } if blocks.len() > MAX_HASHES_PER_MESSAGE => Some(format!(
            "Bodies: {} blocks (max {})",
            blocks.len(),
            MAX_HASHES_PER_MESSAGE
        )),
        _ => None,
    }
}

/// Production keeps bogon rejection fail-closed.
/// Non-mainnet runtime proofs need loopback inbound to be admissible.
#[cfg(feature = "dag")]
fn reject_inbound_bogon_ip(ip: &IpAddr, chain_id: u32) -> bool {
    if chain_id != MAINNET_CHAIN_ID && ip.is_loopback() {
        return false;
    }
    misaka_p2p::is_bogon_ip(ip)
}

/// P0-2: Cheap structural validation before expensive processing.
///
/// For block-carrying messages, validates field sizes, timestamp sanity,
/// and JSON payload bounds BEFORE the ingestion pipeline runs expensive
/// cryptographic verification (lattice signatures, ring proofs, etc.).
///
/// Returns `Some(reason)` if the message should be rejected.
#[cfg(feature = "dag")]
fn cheap_structural_check(msg: &misaka_dag::dag_p2p::DagP2pMessage) -> Option<String> {
    use misaka_dag::dag_p2p::DagP2pMessage;

    match msg {
        DagP2pMessage::DagBlockData {
            header_json,
            txs_json,
            ..
        } => {
            // Reject oversized JSON payloads before deserialization
            if header_json.len() > MAX_BLOCK_JSON_SIZE {
                return Some(format!(
                    "DagBlockData: header_json {} bytes (max {})",
                    header_json.len(),
                    MAX_BLOCK_JSON_SIZE
                ));
            }
            if txs_json.len() > MAX_BLOCK_JSON_SIZE {
                return Some(format!(
                    "DagBlockData: txs_json {} bytes (max {})",
                    txs_json.len(),
                    MAX_BLOCK_JSON_SIZE
                ));
            }
            None
        }
        DagP2pMessage::NewDagBlock {
            timestamp_ms,
            blue_score: _,
            tx_count,
            ..
        } => {
            // Reject blocks with absurd timestamps (> 1 hour in the future)
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let one_hour_ms = 3_600_000;
            if *timestamp_ms > now_ms + one_hour_ms {
                return Some(format!(
                    "NewDagBlock: timestamp_ms {} is >1h in future (now={})",
                    timestamp_ms, now_ms
                ));
            }
            // Reject blocks with absurd tx count
            if *tx_count > 10_000 {
                return Some(format!(
                    "NewDagBlock: tx_count {} exceeds sanity limit 10000",
                    tx_count
                ));
            }
            None
        }
        DagP2pMessage::Headers {
            headers_json,
            count,
            ..
        } => {
            if headers_json.len() > MAX_BLOCK_JSON_SIZE {
                return Some(format!(
                    "Headers: headers_json {} bytes (max {})",
                    headers_json.len(),
                    MAX_BLOCK_JSON_SIZE
                ));
            }
            if *count > 1000 {
                return Some(format!("Headers: count {} exceeds max 1000", count));
            }
            None
        }
        DagP2pMessage::PruningProofData { proof_json }
            if proof_json.len() > MAX_BLOCK_JSON_SIZE =>
        {
            Some(format!(
                "PruningProofData: {} bytes (max {})",
                proof_json.len(),
                MAX_BLOCK_JSON_SIZE
            ))
        }
        DagP2pMessage::DagSnapshotData { snapshot_json }
            if snapshot_json.len() > MAX_BLOCK_JSON_SIZE * 2 =>
        {
            Some(format!(
                "DagSnapshotData: {} bytes (max {})",
                snapshot_json.len(),
                MAX_BLOCK_JSON_SIZE * 2
            ))
        }
        // P0-2 enhancement: Validate per-block body size in Bodies responses.
        // An attacker can send Bodies with one block containing a multi-MB
        // payload that will be fully deserialized and fed into ZKP verification.
        DagP2pMessage::Bodies { blocks } => {
            let total_bytes: usize = blocks.iter().map(|(_, body)| body.len()).sum();
            if total_bytes > MAX_BLOCK_JSON_SIZE * 4 {
                return Some(format!(
                    "Bodies: total payload {} bytes (max {})",
                    total_bytes,
                    MAX_BLOCK_JSON_SIZE * 4
                ));
            }
            for (hash, body) in blocks {
                if body.len() > MAX_BLOCK_JSON_SIZE {
                    return Some(format!(
                        "Bodies: block {} body {} bytes (max {})",
                        hex::encode(&hash[..4]),
                        body.len(),
                        MAX_BLOCK_JSON_SIZE
                    ));
                }
            }
            None
        }
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════
//  Peer Identity
// ═══════════════════════════════════════════════════════════════

/// SEC-L1: Use canonical 32-byte PeerId (matches misaka_p2p::peer_id::PeerId).
///
/// Previous implementation used a 20-byte truncated hash with a different DST,
/// creating two incompatible ID spaces. Now uses the same derivation as PeerRecord
/// so that transport-layer peer IDs match the discovery/scoring layer.
#[cfg(feature = "dag")]
fn derive_peer_id(pk: &ValidatorPqPublicKey, chain_id: u32) -> misaka_p2p::PeerId {
    misaka_p2p::PeerId::from_pubkey(&pk.to_bytes(), chain_id)
}

// ═══════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "dag")]
async fn read_fixed(stream: &mut TcpStream, n: usize, label: &str) -> Result<Vec<u8>, String> {
    let timeout = tokio::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
    let mut buf = vec![0u8; n];
    tokio::time::timeout(timeout, stream.read_exact(&mut buf))
        .await
        .map_err(|_| format!("timeout: {}", label))?
        .map_err(|e| format!("I/O {}: {}", label, e))?;
    Ok(buf)
}

#[cfg(feature = "dag")]
async fn read_lp(stream: &mut TcpStream, max: usize, label: &str) -> Result<Vec<u8>, String> {
    let lb = read_fixed(stream, 4, &format!("{} len", label)).await?;
    let len = u32::from_le_bytes([lb[0], lb[1], lb[2], lb[3]]) as usize;
    if len > max {
        return Err(format!("{} too large: {}", label, len));
    }
    read_fixed(stream, len, label).await
}

#[cfg(feature = "dag")]
async fn write_lp(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    stream
        .write_all(&(data.len() as u32).to_le_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(data).await.map_err(|e| e.to_string())
}

// ═══════════════════════════════════════════════════════════════
//  Responder Handshake (inbound)
// ═══════════════════════════════════════════════════════════════

/// ML-DSA-65 public key size (bytes).
#[cfg(feature = "dag")]
const ML_DSA_PK_LEN: usize = 1952;
/// ML-DSA-65 signature size (bytes).
#[cfg(feature = "dag")]
const ML_DSA_SIG_LEN: usize = 3309;

#[cfg(feature = "dag")]
async fn tcp_responder_handshake(
    stream: &mut TcpStream,
    our_pk: &ValidatorPqPublicKey,
    our_sk: &ValidatorPqSecretKey,
    allowed_initiator_pks: Option<&std::collections::HashSet<Vec<u8>>>,
) -> Result<(HandshakeResult, DirectionalKeys), String> {
    // ── Step 1: Read initiator's KEM PK + nonce_i + version ──
    let kem_pk_buf = read_fixed(stream, 1184, "kem_pk").await?;
    let ephemeral_pk =
        MlKemPublicKey::from_bytes(&kem_pk_buf).map_err(|e| format!("bad kem pk: {}", e))?;

    let id_pk_buf = read_lp(stream, ML_DSA_PK_LEN, "init_pk").await?;
    let initiator_pk =
        ValidatorPqPublicKey::from_bytes(&id_pk_buf).map_err(|e| format!("bad init pk: {}", e))?;

    // SEC-RESP-ALLOWLIST: Reject unknown initiators BEFORE signature verification
    // to avoid CPU-costly ML-DSA verify on unauthenticated connections.
    if let Some(allowed) = allowed_initiator_pks {
        if !allowed.contains(&id_pk_buf) {
            return Err(format!(
                "initiator pk not in allowlist (pk={}..)",
                hex::encode(&id_pk_buf[..8]),
            ));
        }
    }

    // SEC-HS-FRESH: Read initiator's freshness nonce
    let nonce_i_buf = read_fixed(stream, 32, "nonce_i").await?;
    let mut nonce_i = [0u8; 32];
    nonce_i.copy_from_slice(&nonce_i_buf);

    // SEC-HS-VER: Read initiator's protocol version
    let ver_buf = read_fixed(stream, 1, "version").await?;
    let initiator_version = ver_buf[0];

    // ── Steps 2-4: KEM encapsulate + sign ──
    let reply = responder_handle(
        &ephemeral_pk,
        &nonce_i,
        initiator_version,
        our_pk.clone(),
        our_sk,
    )
    .map_err(|e| format!("responder_handle: {}", e))?;

    // ── Send reply: ciphertext + our_pk + sig + nonce_r + our_version ──
    stream
        .write_all(reply.ciphertext.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    write_lp(stream, &our_pk.to_bytes()).await?;
    write_lp(stream, &reply.responder_sig.to_bytes()).await?;
    // SEC-HS-FRESH: Send responder's freshness nonce
    stream
        .write_all(&reply.nonce_r)
        .await
        .map_err(|e| e.to_string())?;
    // SEC-HS-VER: Send responder's protocol version
    stream
        .write_all(&[reply.protocol_version])
        .await
        .map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    // ── Step 7: Read + verify initiator's signature ──
    let init_sig_buf = read_lp(stream, ML_DSA_SIG_LEN, "init_sig").await?;
    let init_sig = ValidatorPqSignature::from_bytes(&init_sig_buf)
        .map_err(|e| format!("bad init sig: {}", e))?;

    let hs = reply
        .verify_initiator(&init_sig, &initiator_pk)
        .map_err(|e| format!("verify init: {}", e))?;

    let keys = DirectionalKeys::derive(&hs.session_key, false);
    Ok((hs, keys))
}

// ═══════════════════════════════════════════════════════════════
//  Initiator Handshake (outbound)
// ═══════════════════════════════════════════════════════════════

/// SEC-C1 fix: `expected_responder_pk` prevents MITM attacks on outbound connections.
///
/// - `Some(pk)` — strict mode: responder MUST present this exact public key.
///   Used when dialing a known peer whose PK is in the peer registry / validator set.
/// - `None` — TOFU (Trust On First Use): any valid responder is accepted.
///   Used only for initial seed connections where we don't know the peer's PK yet.
///   A warning is emitted so operators can audit TOFU events.
#[cfg(feature = "dag")]
async fn tcp_initiator_handshake(
    stream: &mut TcpStream,
    our_pk: &ValidatorPqPublicKey,
    our_sk: &ValidatorPqSecretKey,
    expected_responder_pk: Option<&ValidatorPqPublicKey>,
) -> Result<(HandshakeResult, DirectionalKeys), String> {
    let hs = InitiatorHandshake::new(our_pk.clone()).map_err(|e| format!("kem keygen: {}", e))?;

    // ── Send: ephemeral KEM PK + identity PK + nonce_i + version ──
    stream
        .write_all(hs.ephemeral_pk.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    write_lp(stream, &our_pk.to_bytes()).await?;
    // SEC-HS-FRESH: Send freshness nonce
    stream
        .write_all(&hs.nonce_i)
        .await
        .map_err(|e| e.to_string())?;
    // SEC-HS-VER: Send protocol version
    stream
        .write_all(&[hs.protocol_version])
        .await
        .map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    // ── Read responder reply: ct + pk + sig + nonce_r + version ──
    let ct_buf = read_fixed(stream, 1088, "ct").await?;
    let ciphertext = misaka_pqc::pq_kem::MlKemCiphertext::from_bytes(&ct_buf)
        .map_err(|e| format!("bad ct: {}", e))?;

    let resp_pk_buf = read_lp(stream, ML_DSA_PK_LEN, "resp_pk").await?;
    let responder_pk = ValidatorPqPublicKey::from_bytes(&resp_pk_buf)
        .map_err(|e| format!("bad resp pk: {}", e))?;

    // ── SEC-C1: Verify responder identity BEFORE decapsulation ──
    if let Some(expected) = expected_responder_pk {
        if &responder_pk != expected {
            return Err(format!(
                "MITM: responder pk mismatch (expected {}, got {})",
                hex::encode(&expected.to_bytes()[..8]),
                hex::encode(&responder_pk.to_bytes()[..8]),
            ));
        }
    } else {
        // Phase 2c-B D8: TOFU deleted — always reject unverified responder.
        // SEC-FIX: Removed responder pk bytes from error message to prevent
        // information leakage of peer identities via connection logs.
        return Err(
            "TOFU rejected: no expected_responder_pk provided. Pin the peer's public key."
                .into(),
        );
    }

    let resp_sig_buf = read_lp(stream, ML_DSA_SIG_LEN, "resp_sig").await?;
    let responder_sig = ValidatorPqSignature::from_bytes(&resp_sig_buf)
        .map_err(|e| format!("bad resp sig: {}", e))?;

    // SEC-HS-FRESH: Read responder's freshness nonce
    let nonce_r_buf = read_fixed(stream, 32, "nonce_r").await?;
    let mut nonce_r = [0u8; 32];
    nonce_r.copy_from_slice(&nonce_r_buf);

    // SEC-HS-VER: Read responder's protocol version
    let rver_buf = read_fixed(stream, 1, "resp_version").await?;
    let responder_version = rver_buf[0];
    if responder_version < misaka_p2p::handshake::MIN_PROTOCOL_VERSION {
        return Err(format!(
            "responder version {} below minimum {}",
            responder_version,
            misaka_p2p::handshake::MIN_PROTOCOL_VERSION,
        ));
    }
    let negotiated_version = hs.protocol_version.min(responder_version);

    // ── Decapsulate + derive session key (v3 DST) ──
    use misaka_pqc::pq_kem::{kdf_derive, ml_kem_decapsulate};
    let ss =
        ml_kem_decapsulate(&hs.ephemeral_sk, &ciphertext).map_err(|e| format!("decap: {}", e))?;
    let session_key = kdf_derive(&ss, b"MISAKA-v3:p2p:session-key:", 0);

    // ── Build v3 transcript (matches handshake.rs::build_transcript) ──
    use sha3::{Digest, Sha3_256};
    let ipk_hash: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA-v3:initiator-pk:");
        h.update(&ValidatorPqPublicKey::zero().to_bytes()); // zero placeholder
        h.finalize().into()
    };
    let rpk_hash: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA-v3:responder-pk:");
        h.update(&responder_pk.to_bytes());
        h.finalize().into()
    };
    let mut transcript = Vec::with_capacity(512 + 1184 + 1088);
    transcript.extend_from_slice(b"MISAKA-v3:p2p:transcript:");
    transcript.push(negotiated_version);
    transcript.extend_from_slice(&hs.nonce_i);
    transcript.extend_from_slice(&nonce_r);
    transcript.extend_from_slice(hs.ephemeral_pk.as_bytes());
    transcript.extend_from_slice(ciphertext.as_bytes());
    transcript.extend_from_slice(&ipk_hash);
    transcript.extend_from_slice(&rpk_hash);

    // Verify responder's signature
    validator_verify(&transcript, &responder_sig, &responder_pk)
        .map_err(|e| format!("resp sig verify: {}", e))?;

    // Sign transcript + send
    let our_sig = validator_sign(&transcript, our_sk).map_err(|e| format!("sign: {}", e))?;
    write_lp(stream, &our_sig.to_bytes()).await?;
    stream.flush().await.map_err(|e| e.to_string())?;

    let dir_keys = DirectionalKeys::derive(&session_key, true);
    Ok((
        HandshakeResult {
            session_key,
            peer_pk: responder_pk,
            our_signature: our_sig,
            protocol_version: negotiated_version,
        },
        dir_keys,
    ))
}

// ═══════════════════════════════════════════════════════════════
//  Session Rekey
// ═══════════════════════════════════════════════════════════════

/// Derive new directional keys from the current session key.
///
/// `new_key = SHA3-256(DST || old_session_key || rekey_epoch)`
///
/// Both sides derive identical keys because they share the session_key
/// and increment rekey_epoch in lockstep (triggered at REKEY_THRESHOLD).
#[cfg(feature = "dag")]
fn derive_rekey(
    session_key: &[u8; 32],
    epoch: u64,
    is_initiator: bool,
) -> ([u8; 32], DirectionalKeys) {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA-v3:p2p:rekey:");
    h.update(session_key);
    h.update(&epoch.to_le_bytes());
    let new_session: [u8; 32] = h.finalize().into();
    (
        new_session,
        DirectionalKeys::derive(&new_session, is_initiator),
    )
}

// ═══════════════════════════════════════════════════════════════
//  Encrypted Frame I/O
// ═══════════════════════════════════════════════════════════════

/// Read a raw encrypted frame from the TCP stream (length-prefixed).
///
/// Returns the raw AEAD frame bytes (nonce || ciphertext || tag).
/// Decryption is done separately so that rekey can retry with a new key.
#[cfg(feature = "dag")]
async fn read_raw_frame(reader: &mut tokio::io::ReadHalf<TcpStream>) -> Result<Vec<u8>, AeadError> {
    let mut len_buf = [0u8; FRAME_HEADER_SIZE];
    tokio::time::timeout(
        tokio::time::Duration::from_secs(READ_TIMEOUT_SECS),
        reader.read_exact(&mut len_buf),
    )
    .await
    .map_err(|_| AeadError::Io("timeout".into()))?
    .map_err(|e| AeadError::Io(e.to_string()))?;

    let frame_len = u32::from_le_bytes(len_buf);
    if frame_len > MAX_FRAME_SIZE {
        return Err(AeadError::FrameTooLarge { size: frame_len });
    }
    if frame_len < (NONCE_SIZE + TAG_SIZE) as u32 {
        return Err(AeadError::DecryptFailed);
    }

    let mut frame = vec![0u8; frame_len as usize];
    reader
        .read_exact(&mut frame)
        .await
        .map_err(|e| AeadError::Io(e.to_string()))?;
    Ok(frame)
}

#[cfg(feature = "dag")]
#[allow(dead_code)]
async fn read_encrypted_frame(
    reader: &mut tokio::io::ReadHalf<TcpStream>,
    recv_key: &[u8; 32],
) -> Result<Vec<u8>, AeadError> {
    let frame = read_raw_frame(reader).await?;
    decrypt_frame(recv_key, &frame)
}

// ═══════════════════════════════════════════════════════════════
//  Per-Peer Connection Handler
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "dag")]
async fn handle_peer(
    stream: TcpStream,
    peer_id: misaka_p2p::PeerId,
    keys: DirectionalKeys,
    inbound_tx: mpsc::Sender<InboundDagEvent>,
    mut peer_out_rx: mpsc::Receiver<Vec<u8>>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let ph = peer_id.short_hex();

    let wph = ph.clone();
    let initial_session_key = keys.send_key;
    let mut current_send_key = keys.send_key;
    let wh = tokio::spawn(async move {
        let mut nonce = NonceCounter::new();
        let mut rekey_epoch = 0u64;
        let mut rekey_sent = false;
        let mut session_seed = initial_session_key;

        while let Some(pt) = peer_out_rx.recv().await {
            // ── SEC-L2: Proactive rekey at 90% nonce threshold ──
            // Send an explicit Rekey message so the receiver can switch keys
            // BEFORE the nonce is exhausted. This is much more reliable than
            // the fallback "AEAD failure → retry with new key" path (C-2).
            if !rekey_sent && nonce.current() >= REKEY_WARN_AT {
                let next_epoch = rekey_epoch + 1;
                let rekey_payload = misaka_p2p::secure_transport::encode_binary_message(
                    misaka_p2p::secure_transport::MsgType::Rekey,
                    &next_epoch.to_le_bytes(),
                );
                // Send Rekey notification under the CURRENT (old) key
                match encode_wire_frame(&current_send_key, &mut nonce, &rekey_payload) {
                    Ok(w) => {
                        if writer.write_all(&w).await.is_err() || writer.flush().await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
                // Now switch to new key
                rekey_epoch = next_epoch;
                let (new_seed, new_keys) = derive_rekey(&session_seed, rekey_epoch, true);
                session_seed = new_seed;
                current_send_key = new_keys.send_key;
                nonce = NonceCounter::new();
                rekey_sent = false; // Reset for next epoch
                info!("Peer {} proactive rekey (epoch={})", wph, rekey_epoch);
            }

            match encode_wire_frame(&current_send_key, &mut nonce, &pt) {
                Ok(w) => {
                    if writer.write_all(&w).await.is_err() || writer.flush().await.is_err() {
                        break;
                    }
                }
                Err(AeadError::NonceExhausted) => {
                    // Fallback: proactive rekey didn't fire (shouldn't happen,
                    // but defense-in-depth). Do emergency rekey.
                    rekey_epoch += 1;
                    let (new_seed, new_keys) = derive_rekey(&session_seed, rekey_epoch, true);
                    session_seed = new_seed;
                    current_send_key = new_keys.send_key;
                    nonce = NonceCounter::new();
                    rekey_sent = false;
                    warn!(
                        "Peer {} emergency rekey (epoch={}) — proactive rekey missed",
                        wph, rekey_epoch
                    );

                    match encode_wire_frame(&current_send_key, &mut nonce, &pt) {
                        Ok(w) => {
                            if writer.write_all(&w).await.is_err() || writer.flush().await.is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                Err(_) => break,
            }
        }
        debug!("Peer {} writer done", wph);
    });

    // ── SEC-C2: Reader with rekey retry ──
    // When the sender rekeys (nonce exhausted), its next frame is encrypted
    // with the new key. The receiver's first decrypt attempt fails because
    // it's still using the old key. Instead of losing the frame, we keep
    // the raw bytes and retry decryption with the next-epoch key.
    let mut current_recv_key = keys.recv_key;
    let mut recv_session_seed = keys.recv_key;
    let mut recv_rekey_epoch = 0u64;
    /// Maximum consecutive rekey attempts before treating as genuine corruption.
    const MAX_REKEY_RETRIES: u32 = 2;

    // ── P0-3: Per-peer message rate counter ──
    let mut peer_msg_count: u32 = 0;
    let mut peer_rate_window_start = tokio::time::Instant::now();
    let peer_msg_limit = peer_max_messages_per_sec();

    loop {
        let raw_frame = match read_raw_frame(&mut reader).await {
            Ok(f) => f,
            Err(AeadError::Io(e)) if e.contains("timeout") => {
                // Read timeout is normal for idle connections — send ping instead of disconnect
                debug!("Peer {} read timeout (idle)", ph);
                break;
            }
            Err(e) => {
                debug!("Peer {} read: {}", ph, e);
                break;
            }
        };

        // Try decryption with current key, retry with rekeyed key on failure
        let plaintext = match decrypt_frame(&current_recv_key, &raw_frame) {
            Ok(pt) => pt,
            Err(AeadError::DecryptFailed) => {
                // Might be a rekey boundary — try next epoch(s)
                let mut recovered = None;
                for attempt in 1..=MAX_REKEY_RETRIES {
                    let try_epoch = recv_rekey_epoch + attempt as u64;
                    let (new_seed, new_keys) = derive_rekey(&recv_session_seed, try_epoch, false);
                    match decrypt_frame(&new_keys.recv_key, &raw_frame) {
                        Ok(pt) => {
                            // Rekey succeeded — commit the new state
                            recv_rekey_epoch = try_epoch;
                            recv_session_seed = new_seed;
                            current_recv_key = new_keys.recv_key;
                            info!(
                                "Peer {} recv rekeyed (epoch={}) — frame recovered",
                                ph, recv_rekey_epoch
                            );
                            recovered = Some(pt);
                            break;
                        }
                        Err(_) => continue,
                    }
                }
                match recovered {
                    Some(pt) => pt,
                    None => {
                        // Genuine AEAD failure — data corruption or active tampering
                        warn!(
                            "Peer {} AEAD auth failed after rekey retries — disconnecting",
                            ph
                        );
                        break;
                    }
                }
            }
            Err(e) => {
                debug!("Peer {} decrypt: {}", ph, e);
                break;
            }
        };

        // ── SEC-L2: Check for transport control messages (Rekey/RekeyAck) ──
        // These use the binary message codec (MsgType tag byte) and are handled
        // at the transport layer, never forwarded to the consensus event loop.
        //
        // Regular DAG messages are JSON-encoded and lack the binary tag, so we
        // distinguish by trying binary decode first (cheap: 1-byte check).
        if plaintext.len() >= 5 {
            if let Ok((msg_type, payload)) =
                misaka_p2p::secure_transport::decode_binary_message(&plaintext)
            {
                if msg_type == misaka_p2p::secure_transport::MsgType::Rekey {
                    if payload.len() >= 8 {
                        let new_epoch =
                            u64::from_le_bytes(payload[..8].try_into().unwrap_or([0u8; 8]));
                        // Switch recv key to the announced epoch
                        if new_epoch > recv_rekey_epoch {
                            let (new_seed, new_keys) =
                                derive_rekey(&recv_session_seed, new_epoch, false);
                            recv_rekey_epoch = new_epoch;
                            recv_session_seed = new_seed;
                            current_recv_key = new_keys.recv_key;
                            info!(
                                "Peer {} explicit rekey received (epoch={})",
                                ph, recv_rekey_epoch
                            );
                        }
                    }
                    continue; // Don't forward to consensus
                }
                if msg_type == misaka_p2p::secure_transport::MsgType::RekeyAck {
                    // Informational only — sender doesn't need to act on ack
                    debug!("Peer {} rekey ack received", ph);
                    continue;
                }
                // Other binary MsgTypes (Ping/Pong etc) could be handled here
                // in the future. For now, fall through to JSON decode.
            }
        }

        match serde_json::from_slice::<misaka_dag::dag_p2p::DagP2pMessage>(&plaintext) {
            Ok(msg) => {
                // ── P0-1: Message item count limits ──
                // Reject messages with excessively large vector fields BEFORE
                // forwarding to the event loop. This prevents a peer from
                // sending a single message with 100,000 hashes that triggers
                // O(n) lookups in the DAG store.
                if let Some(reason) = validate_message_limits(&msg) {
                    warn!("Peer {} message rejected (item limit): {}", ph, reason);
                    continue;
                }

                // ── P0-2: Cheap structural validation ──
                // For block-carrying messages, validate basic structure
                // (field sizes, timestamp sanity) BEFORE feeding into the
                // expensive ingestion/verification pipeline.
                if let Some(reason) = cheap_structural_check(&msg) {
                    warn!("Peer {} message rejected (structural): {}", ph, reason);
                    continue;
                }

                // ── P0-3: Per-peer message rate gate ──
                // Track message count per peer in a sliding window.
                // If a peer exceeds the limit, drop the message silently
                // (the peer will be disconnected on the next tick by
                // PeerDagState::record_message → ban).
                peer_msg_count += 1;
                let now = tokio::time::Instant::now();
                if now.duration_since(peer_rate_window_start) >= tokio::time::Duration::from_secs(1)
                {
                    // Reset window
                    peer_rate_window_start = now;
                    peer_msg_count = 1;
                }
                if peer_msg_count > peer_msg_limit {
                    warn!(
                        "Peer {} rate limited ({}/s, limit={}), dropping message",
                        ph, peer_msg_count, peer_msg_limit
                    );
                    continue;
                }

                if inbound_tx
                    .send(InboundDagEvent {
                        peer_id,
                        message: msg,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(e) => {
                warn!("Peer {} bad msg: {}", ph, e);
            }
        }
    }
    wh.abort();
    info!("Peer {} disconnected", ph);
}

// ═══════════════════════════════════════════════════════════════
//  Peer Registry
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "dag")]
struct PeerRegistry {
    peers: HashMap<misaka_p2p::PeerId, mpsc::Sender<Vec<u8>>>,
}

#[cfg(feature = "dag")]
impl PeerRegistry {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }
    fn insert(&mut self, id: misaka_p2p::PeerId, tx: mpsc::Sender<Vec<u8>>) {
        self.peers.insert(id, tx);
    }
    fn remove(&mut self, id: &misaka_p2p::PeerId) {
        self.peers.remove(id);
    }
    fn has(&self, id: &misaka_p2p::PeerId) -> bool {
        self.peers.contains_key(id)
    }
    async fn send(&self, target: Option<&misaka_p2p::PeerId>, data: &[u8]) {
        match target {
            Some(id) => {
                if let Some(tx) = self.peers.get(id) {
                    let _ = tx.send(data.to_vec()).await;
                }
            }
            None => {
                for tx in self.peers.values() {
                    let _ = tx.send(data.to_vec()).await;
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeMode;
    use misaka_crypto::validator_sig::generate_validator_keypair;
    use misaka_dag::dag_block::{DagBlockHeader, DAG_VERSION, ZERO_HASH};
    use misaka_dag::dag_p2p::DagP2pMessage;
    use misaka_dag::dag_p2p::DAG_PROTOCOL_VERSION;
    use misaka_dag::dag_store::ThreadSafeDagStore;
    use misaka_dag::reachability::ReachabilityStore;
    use misaka_dag::{
        DagCheckpoint, DagMempool, DagNodeState, DagStateManager, GhostDagEngine,
        IngestionPipeline, VirtualState,
    };
    use misaka_storage::utxo_set::UtxoSet;
    use std::collections::{HashMap, HashSet};
    use std::net::{SocketAddr, TcpListener as StdTcpListener};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::RwLock;
    use tokio::time::{timeout, Duration};

    fn make_test_dag_state() -> DagNodeState {
        let genesis_header = DagBlockHeader {
            version: DAG_VERSION,
            parents: vec![],
            timestamp_ms: 1_700_000_000_000,
            tx_root: ZERO_HASH,
            proposer_id: [0u8; 32],
            nonce: 0,
            blue_score: 0,
            bits: 0,
        };
        let genesis_hash = genesis_header.compute_hash();

        DagNodeState {
            dag_store: Arc::new(ThreadSafeDagStore::new(genesis_hash, genesis_header)),
            ghostdag: GhostDagEngine::new(18, genesis_hash),
            state_manager: DagStateManager::new(HashSet::new(), HashSet::new()),
            utxo_set: UtxoSet::new(32),
            virtual_state: VirtualState::new(genesis_hash),
            ingestion_pipeline: IngestionPipeline::new([genesis_hash].into_iter().collect()),
            quarantined_blocks: HashSet::new(),
            mempool: DagMempool::new(32),
            chain_id: 31337,
            validator_count: 2,
            known_validators: Vec::new(),
            proposer_id: [0xAB; 32],
            sr_index: 0,
            num_active_srs: 1,
            runtime_active_sr_validator_ids: Vec::new(),
            local_validator: None,
            genesis_hash,
            snapshot_path: PathBuf::from("/tmp/misaka-dag-p2p-transport-test-snapshot.json"),
            latest_checkpoint: Some(DagCheckpoint {
                block_hash: genesis_hash,
                blue_score: 0,
                utxo_root: ZERO_HASH,
                total_spent_count: 0,
                total_applied_txs: 0,
                timestamp_ms: 1_700_000_000_000,
            }),
            latest_checkpoint_vote: None,
            latest_checkpoint_finality: None,
            checkpoint_vote_pool: HashMap::new(),
            attestation_rpc_peers: Vec::new(),
            blocks_produced: 0,
            reachability: ReachabilityStore::new(genesis_hash),
            persistent_backend: None,
            faucet_cooldowns: HashMap::new(),
            pending_transactions: HashMap::new(),
        }
    }

    fn reserve_local_addr() -> SocketAddr {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind local addr");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        addr
    }

    #[tokio::test]
    async fn test_initial_dag_hello_bytes_reflects_local_state() {
        let state = Arc::new(RwLock::new(make_test_dag_state()));
        let genesis_hash = state.read().await.genesis_hash;

        let bytes = initial_dag_hello_bytes(
            &state,
            31337,
            "node-a",
            NodeMode::Public,
            "127.0.0.1:6690".parse().unwrap(),
        )
        .await
        .expect("bootstrap hello bytes");

        let msg: misaka_dag::dag_p2p::DagP2pMessage =
            serde_json::from_slice(&bytes).expect("decode bootstrap hello");
        match msg {
            misaka_dag::dag_p2p::DagP2pMessage::DagHello {
                chain_id,
                dag_version,
                blue_score,
                tips,
                pruning_point,
                node_name,
                mode,
                listen_addr,
            } => {
                assert_eq!(chain_id, 31337);
                assert_eq!(dag_version, DAG_PROTOCOL_VERSION);
                assert_eq!(blue_score, 0);
                assert!(!tips.is_empty());
                assert_eq!(tips[0], genesis_hash);
                assert_eq!(pruning_point, genesis_hash);
                assert_eq!(node_name, "node-a");
                assert_eq!(mode, "public");
                assert_eq!(listen_addr.as_deref(), Some("127.0.0.1:6690"));
            }
            other => panic!("unexpected bootstrap message: {:?}", other),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_tcp_handshake_allows_first_dag_frame_roundtrip() {
        let keypair_a = generate_validator_keypair();
        let keypair_b = generate_validator_keypair();
        let listen_addr = reserve_local_addr();
        let listener = TcpListener::bind(listen_addr)
            .await
            .expect("bind transport listener");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let (_hs, keys) =
                tcp_responder_handshake(&mut stream, &keypair_a.public_key, &keypair_a.secret_key, None)
                    .await
                    .expect("responder handshake");
            let (mut reader, _) = tokio::io::split(stream);
            let plaintext = read_encrypted_frame(&mut reader, &keys.recv_key)
                .await
                .expect("decrypt first dag frame");
            serde_json::from_slice::<DagP2pMessage>(&plaintext).expect("decode dag frame")
        });

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(listen_addr).await.expect("connect");
            let (_hs, keys) = tcp_initiator_handshake(
                &mut stream,
                &keypair_b.public_key,
                &keypair_b.secret_key,
                None,
            )
            .await
            .expect("initiator handshake");
            let (_, mut writer) = tokio::io::split(stream);
            let mut nonce = NonceCounter::new();
            let message = DagP2pMessage::DagHello {
                chain_id: 31337,
                dag_version: DAG_PROTOCOL_VERSION,
                blue_score: 0,
                tips: vec![[0u8; 32]],
                pruning_point: [0u8; 32],
                node_name: "transport-b".to_string(),
                mode: NodeMode::Public.to_string(),
                listen_addr: Some("127.0.0.1:6691".to_string()),
            };
            let payload = serde_json::to_vec(&message).expect("serialize dag hello");
            let frame =
                encode_wire_frame(&keys.send_key, &mut nonce, &payload).expect("encode dag frame");
            writer.write_all(&frame).await.expect("write dag frame");
            writer.flush().await.expect("flush dag frame");
            message
        });

        let received = timeout(Duration::from_secs(5), server)
            .await
            .expect("server timeout")
            .expect("server task join");
        let sent = client.await.expect("client task join");

        match (sent, received) {
            (
                DagP2pMessage::DagHello {
                    chain_id: sent_chain_id,
                    dag_version: sent_version,
                    node_name: sent_name,
                    ..
                },
                DagP2pMessage::DagHello {
                    chain_id: recv_chain_id,
                    dag_version: recv_version,
                    node_name: recv_name,
                    ..
                },
            ) => {
                assert_eq!(recv_chain_id, sent_chain_id);
                assert_eq!(recv_version, sent_version);
                assert_eq!(recv_name, sent_name);
            }
            other => panic!("unexpected dag frame roundtrip: {:?}", other),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_tcp_handshake_allows_first_dag_frame_roundtrip_from_responder() {
        let keypair_a = generate_validator_keypair();
        let keypair_b = generate_validator_keypair();
        let listen_addr = reserve_local_addr();
        let listener = TcpListener::bind(listen_addr)
            .await
            .expect("bind transport listener");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let (_hs, keys) =
                tcp_responder_handshake(&mut stream, &keypair_a.public_key, &keypair_a.secret_key, None)
                    .await
                    .expect("responder handshake");
            let (_, mut writer) = tokio::io::split(stream);
            let mut nonce = NonceCounter::new();
            let message = DagP2pMessage::DagHello {
                chain_id: 31337,
                dag_version: DAG_PROTOCOL_VERSION,
                blue_score: 7,
                tips: vec![[0xAA; 32]],
                pruning_point: [0xBB; 32],
                node_name: "transport-a".to_string(),
                mode: NodeMode::Public.to_string(),
                listen_addr: Some("127.0.0.1:6690".to_string()),
            };
            let payload = serde_json::to_vec(&message).expect("serialize dag hello");
            let frame =
                encode_wire_frame(&keys.send_key, &mut nonce, &payload).expect("encode dag frame");
            writer.write_all(&frame).await.expect("write dag frame");
            writer.flush().await.expect("flush dag frame");
            message
        });

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(listen_addr).await.expect("connect");
            let (_hs, keys) = tcp_initiator_handshake(
                &mut stream,
                &keypair_b.public_key,
                &keypair_b.secret_key,
                None,
            )
            .await
            .expect("initiator handshake");
            let (mut reader, _) = tokio::io::split(stream);
            let plaintext = read_encrypted_frame(&mut reader, &keys.recv_key)
                .await
                .expect("decrypt first dag frame");
            serde_json::from_slice::<DagP2pMessage>(&plaintext).expect("decode dag frame")
        });

        let sent = timeout(Duration::from_secs(5), server)
            .await
            .expect("server timeout")
            .expect("server task join");
        let received = client.await.expect("client task join");

        match (sent, received) {
            (
                DagP2pMessage::DagHello {
                    chain_id: sent_chain_id,
                    dag_version: sent_version,
                    node_name: sent_name,
                    ..
                },
                DagP2pMessage::DagHello {
                    chain_id: recv_chain_id,
                    dag_version: recv_version,
                    node_name: recv_name,
                    ..
                },
            ) => {
                assert_eq!(recv_chain_id, sent_chain_id);
                assert_eq!(recv_version, sent_version);
                assert_eq!(recv_name, sent_name);
            }
            other => panic!("unexpected dag frame roundtrip: {:?}", other),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_handle_peer_exchanges_initial_dag_hello_bidirectionally() {
        let keypair_a = generate_validator_keypair();
        let keypair_b = generate_validator_keypair();
        let listen_addr_a = reserve_local_addr();
        let listen_addr_b = reserve_local_addr();
        let listener = TcpListener::bind(listen_addr_a)
            .await
            .expect("bind transport listener");

        let state_a = Arc::new(RwLock::new(make_test_dag_state()));
        let state_b = Arc::new(RwLock::new(make_test_dag_state()));
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<InboundDagEvent>(8);

        let server_inbound = inbound_tx.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let (hs, dk) =
                tcp_responder_handshake(&mut stream, &keypair_a.public_key, &keypair_a.secret_key, None)
                    .await
                    .expect("responder handshake");
            let peer_id = derive_peer_id(&hs.peer_pk, 31337);
            let (otx, orx) = mpsc::channel::<Vec<u8>>(PEER_OUTBOUND_CAPACITY);
            let hello = initial_dag_hello_bytes(
                &state_a,
                31337,
                "transport-a",
                NodeMode::Public,
                listen_addr_a,
            )
            .await
            .expect("initial hello a");
            otx.send(hello).await.expect("queue hello a");
            handle_peer(stream, peer_id, dk, server_inbound, orx).await;
        });

        let client_inbound = inbound_tx.clone();
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(listen_addr_a).await.expect("connect");
            let (hs, dk) = tcp_initiator_handshake(
                &mut stream,
                &keypair_b.public_key,
                &keypair_b.secret_key,
                None,
            )
            .await
            .expect("initiator handshake");
            let peer_id = derive_peer_id(&hs.peer_pk, 31337);
            let (otx, orx) = mpsc::channel::<Vec<u8>>(PEER_OUTBOUND_CAPACITY);
            let hello = initial_dag_hello_bytes(
                &state_b,
                31337,
                "transport-b",
                NodeMode::Public,
                listen_addr_b,
            )
            .await
            .expect("initial hello b");
            otx.send(hello).await.expect("queue hello b");
            handle_peer(stream, peer_id, dk, client_inbound, orx).await;
        });

        let first = timeout(Duration::from_secs(5), inbound_rx.recv())
            .await
            .expect("first inbound timeout")
            .expect("first inbound message");
        let second = timeout(Duration::from_secs(5), inbound_rx.recv())
            .await
            .expect("second inbound timeout")
            .expect("second inbound message");

        for event in [first, second] {
            match event.message {
                DagP2pMessage::DagHello { chain_id, .. } => assert_eq!(chain_id, 31337),
                other => panic!("expected DagHello, got {:?}", other),
            }
        }

        server.abort();
        client.abort();
    }

    #[test]
    fn test_reject_inbound_bogon_ip_allows_loopback_on_non_mainnet() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(!reject_inbound_bogon_ip(&loopback, 2));
        assert!(!reject_inbound_bogon_ip(&loopback, 31337));
    }

    #[test]
    fn test_reject_inbound_bogon_ip_keeps_mainnet_fail_closed() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let private_ip: IpAddr = "10.0.0.5".parse().unwrap();
        assert!(reject_inbound_bogon_ip(&loopback, MAINNET_CHAIN_ID));
        assert!(reject_inbound_bogon_ip(&private_ip, MAINNET_CHAIN_ID));
    }

    #[test]
    fn test_reject_inbound_bogon_ip_still_rejects_private_ipv4_on_non_mainnet() {
        let private_ip: IpAddr = "10.0.0.5".parse().unwrap();
        assert!(reject_inbound_bogon_ip(&private_ip, 2));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_seed_connection_registry_clears_after_disconnect() {
        let responder = generate_validator_keypair();
        let initiator = generate_validator_keypair();
        let seed_addr = reserve_local_addr();
        let local_listen_addr = reserve_local_addr();
        let listener = TcpListener::bind(seed_addr)
            .await
            .expect("bind seed listener");
        let state = Arc::new(RwLock::new(make_test_dag_state()));
        let reg = Arc::new(RwLock::new(PeerRegistry::new()));
        let active_seed_connections = Arc::new(RwLock::new(HashSet::<SocketAddr>::new()));
        let (inbound_tx, _inbound_rx) = mpsc::channel::<InboundDagEvent>(8);

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let _ =
                tcp_responder_handshake(&mut stream, &responder.public_key, &responder.secret_key, None)
                    .await
                    .expect("responder handshake");
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let _peer_id = connect_to_peer(
            seed_addr,
            &initiator.public_key,
            &initiator.secret_key,
            None,
            &inbound_tx,
            &reg,
            &state,
            31337,
            "seed-test",
            NodeMode::Public,
            local_listen_addr,
            Some(&active_seed_connections),
        )
        .await
        .expect("connect to seed");

        assert!(active_seed_connections.read().await.contains(&seed_addr));

        timeout(Duration::from_secs(5), async {
            loop {
                if !active_seed_connections.read().await.contains(&seed_addr) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("seed registry cleared after disconnect");

        server.await.expect("server task");
    }
}

// ═══════════════════════════════════════════════════════════════
//  Outbound Connect
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "dag")]
async fn connect_to_peer(
    addr: SocketAddr,
    pk: &ValidatorPqPublicKey,
    sk: &ValidatorPqSecretKey,
    expected_peer_pk: Option<&ValidatorPqPublicKey>,
    itx: &mpsc::Sender<InboundDagEvent>,
    reg: &Arc<RwLock<PeerRegistry>>,
    state: &Arc<RwLock<DagNodeState>>,
    chain_id: u32,
    node_name: &str,
    node_mode: NodeMode,
    listen_addr: SocketAddr,
    seed_connections: Option<&Arc<RwLock<HashSet<SocketAddr>>>>,
) -> Result<misaka_p2p::PeerId, String> {
    if let Some(seed_connections) = seed_connections {
        if seed_connections.read().await.contains(&addr) {
            return Err(format!("seed already connected: {}", addr));
        }
    }

    let mut stream = tokio::time::timeout(
        tokio::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| format!("connect timeout: {}", addr))?
    .map_err(|e| format!("connect {}: {}", addr, e))?;

    let (hs, dk) = tcp_initiator_handshake(&mut stream, pk, sk, expected_peer_pk).await?;
    let peer_id = derive_peer_id(&hs.peer_pk, chain_id);

    if reg.read().await.has(&peer_id) {
        return Err(format!("already connected: {}", peer_id.short_hex()));
    }

    let (otx, orx) = mpsc::channel::<Vec<u8>>(PEER_OUTBOUND_CAPACITY);
    reg.write().await.insert(peer_id, otx);
    if let Some(seed_connections) = seed_connections {
        seed_connections.write().await.insert(addr);
    }
    if let Some(hello_bytes) =
        initial_dag_hello_bytes(state, chain_id, node_name, node_mode, listen_addr).await
    {
        let tx = reg
            .read()
            .await
            .peers
            .get(&peer_id)
            .cloned()
            .ok_or_else(|| "peer sender missing after connect".to_string())?;
        if let Err(e) = tx.send(hello_bytes).await {
            warn!(
                "Failed to queue initial DAG hello for peer {}: {}",
                peer_id.short_hex(),
                e
            );
        }
    }

    let itx2 = itx.clone();
    let reg2 = reg.clone();
    let seed_connections = seed_connections.cloned();
    tokio::spawn(async move {
        handle_peer(stream, peer_id, dk, itx2, orx).await;
        reg2.write().await.remove(&peer_id);
        if let Some(seed_connections) = seed_connections {
            seed_connections.write().await.remove(&addr);
        }
    });

    Ok(peer_id)
}

#[cfg(feature = "dag")]
async fn initial_dag_hello_bytes(
    state: &Arc<RwLock<DagNodeState>>,
    chain_id: u32,
    node_name: &str,
    node_mode: NodeMode,
    listen_addr: SocketAddr,
) -> Option<Vec<u8>> {
    let guard = state.read().await;
    let snapshot = guard.dag_store.snapshot();
    let tips = snapshot.get_tips();
    let pruning_point = guard
        .latest_checkpoint
        .as_ref()
        .map(|cp| cp.block_hash)
        .unwrap_or(guard.genesis_hash);

    let hello = misaka_dag::dag_p2p::DagP2pMessage::DagHello {
        chain_id,
        dag_version: misaka_dag::dag_p2p::DAG_PROTOCOL_VERSION,
        blue_score: guard.dag_store.max_blue_score(),
        tips,
        pruning_point,
        node_name: node_name.to_string(),
        mode: node_mode.to_string(),
        listen_addr: node_mode
            .advertises_address()
            .then(|| listen_addr.to_string()),
    };
    serde_json::to_vec(&hello).ok()
}

#[cfg(feature = "dag")]
#[allow(dead_code)]
async fn send_initial_dag_hello(
    tx: &mpsc::Sender<Vec<u8>>,
    state: &Arc<RwLock<DagNodeState>>,
    chain_id: u32,
    node_name: &str,
    node_mode: NodeMode,
    listen_addr: SocketAddr,
) {
    match initial_dag_hello_bytes(state, chain_id, node_name, node_mode, listen_addr).await {
        Some(hello_bytes) => {
            if let Err(e) = tx.send(hello_bytes).await {
                warn!("Failed to queue initial DAG hello: {}", e);
            }
        }
        None => warn!("Failed to build initial DAG hello"),
    }
}

// ═══════════════════════════════════════════════════════════════
//  Main Entry Point
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "dag")]
pub async fn run_dag_p2p_transport(
    listen_addr: SocketAddr,
    our_pk: ValidatorPqPublicKey,
    our_sk: ValidatorPqSecretKey,
    inbound_tx: mpsc::Sender<InboundDagEvent>,
    mut outbound_rx: mpsc::Receiver<OutboundDagEvent>,
    chain_id: u32,
    node_name: String,
    node_mode: NodeMode,
    state: Arc<RwLock<DagNodeState>>,
    seed_addrs: Vec<SocketAddr>,
    /// Phase 2b' (M7'): Parsed seed entries with pinned ML-DSA-65 public keys.
    parsed_seeds: Vec<misaka_types::seed_entry::SeedEntry>,
    observation: Arc<RwLock<crate::dag_p2p_surface::DagP2pObservationState>>,
    guard_config: misaka_p2p::GuardConfig,
) {
    let seed_connect_attempts = std::env::var("MISAKA_DAG_SEED_CONNECT_ATTEMPTS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(5);
    let seed_connect_initial_delay_ms = std::env::var("MISAKA_DAG_SEED_CONNECT_INITIAL_DELAY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(1000);
    let seed_connect_max_delay_ms = std::env::var("MISAKA_DAG_SEED_CONNECT_MAX_DELAY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(30_000);
    let seed_redial_interval_ms = std::env::var("MISAKA_DAG_SEED_REDIAL_INTERVAL_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(5_000);

    let listener = match TcpListener::bind(listen_addr).await {
        Ok(l) => {
            info!("DAG P2P listening on {}", listen_addr);
            l
        }
        Err(e) => {
            error!("Bind P2P {}: {}", listen_addr, e);
            return;
        }
    };

    let reg = Arc::new(RwLock::new(PeerRegistry::new()));
    let active_seed_connections = Arc::new(RwLock::new(HashSet::<SocketAddr>::new()));

    // Phase 2b' (M7'): Build seed PK lookup map for pinning.
    let seed_pk_map: std::collections::HashMap<String, ValidatorPqPublicKey> = parsed_seeds
        .iter()
        .filter_map(|entry| {
            let pk_bytes = entry.transport_pubkey_bytes()?;
            let pk = ValidatorPqPublicKey::from_bytes(&pk_bytes).ok()?;
            Some((entry.address.clone(), pk))
        })
        .collect();
    let seed_pk_map = Arc::new(seed_pk_map);

    // Maintain seed connectivity for the lifetime of the transport.
    for addr in seed_addrs {
        let (pk, sk, itx, r, st, name, mode, seed_connections, seed_pks) = (
            our_pk.clone(),
            our_sk.clone(),
            inbound_tx.clone(),
            reg.clone(),
            state.clone(),
            node_name.clone(),
            node_mode,
            active_seed_connections.clone(),
            seed_pk_map.clone(),
        );
        tokio::spawn(async move {
            let mut delay = seed_connect_initial_delay_ms;
            let mut attempt = 0u32;
            loop {
                if seed_connections.read().await.contains(&addr) {
                    attempt = 0;
                    delay = seed_connect_initial_delay_ms;
                    tokio::time::sleep(tokio::time::Duration::from_millis(seed_redial_interval_ms))
                        .await;
                    continue;
                }

                attempt = attempt.saturating_add(1);
                // Phase 2b' (M7'): look up pinned PK for this seed.
                let addr_str = addr.to_string();
                let pinned_pk = seed_pks.get(&addr_str);
                if pinned_pk.is_none() {
                    // SEC-FIX: On mainnet, unpinned seed PKs are a fatal configuration error.
                    // Without pinned PKs, TOFU is rejected (compile_error in release) and
                    // the node cannot connect to ANY seed — network participation impossible.
                    if chain_id == 1 {
                        error!(
                            "FATAL: Seed {} has no pinned PK on mainnet. \
                             All seed entries MUST include public keys. \
                             Configure --seed-pubkeys or update testnet-seeds.txt.",
                            addr
                        );
                        // Continue retrying in case the config is hot-reloaded,
                        // but log at ERROR level to make this unmissable.
                    } else {
                        warn!(
                            "Seed {} has no pinned PK — skipping (configure --seed-pubkeys)",
                            addr
                        );
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                    continue;
                }

                match connect_to_peer(
                    addr,
                    &pk,
                    &sk,
                    pinned_pk, // Phase 2b': pinned PK, no TOFU
                    &itx,
                    &r,
                    &st,
                    chain_id,
                    &name,
                    mode,
                    listen_addr,
                    Some(&seed_connections),
                )
                .await
                {
                    Ok(id) => {
                        info!("Seed {} ok (attempt {}): {}", addr, attempt, id.short_hex());
                        attempt = 0;
                        delay = seed_connect_initial_delay_ms;
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            seed_redial_interval_ms,
                        ))
                        .await;
                        continue;
                    }
                    Err(e) => {
                        if attempt <= seed_connect_attempts {
                            warn!("Seed {} attempt {}: {}", addr, attempt, e);
                        } else {
                            debug!("Seed {} retry {}: {}", addr, attempt, e);
                        }
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                delay = (delay * 2).min(seed_connect_max_delay_ms);
            }
        });
    }

    // Outbound router
    let reg2 = reg.clone();
    tokio::spawn(async move {
        while let Some(ev) = outbound_rx.recv().await {
            if let Ok(j) = serde_json::to_vec(&ev.message) {
                reg2.read().await.send(ev.peer_id.as_ref(), &j).await;
            }
        }
    });

    // Discovery gossip: periodically send GetPeers + connect discovered addresses
    {
        let disc_reg = reg.clone();
        let disc_obs = observation;
        let disc_pk = our_pk.clone();
        let disc_sk = our_sk.clone();
        let disc_itx = inbound_tx.clone();
        let disc_state = state.clone();
        let disc_node_name = node_name.clone();
        let disc_node_mode = node_mode;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(
                DISCOVERY_GOSSIP_INTERVAL_SECS,
            ));
            loop {
                ticker.tick().await;

                // 1. Broadcast GetPeers to all connected peers
                let get_peers_msg = misaka_dag::dag_p2p::DagP2pMessage::GetPeers;
                if let Ok(j) = serde_json::to_vec(&get_peers_msg) {
                    disc_reg.read().await.send(None, &j).await;
                }

                // 2. Drain discovered peer addresses from observation state
                let discovered = {
                    let mut obs = disc_obs.write().await;
                    std::mem::take(&mut obs.discovered_peers)
                };

                if discovered.is_empty() {
                    continue;
                }

                // 3. Attempt to connect to discovered peers (up to cap)
                let current_count = disc_reg.read().await.peers.len();
                if current_count >= MAX_DISCOVERY_CONNECTIONS {
                    debug!(
                        "Discovery: already at {} peers (max={}), skipping {} discovered",
                        current_count,
                        MAX_DISCOVERY_CONNECTIONS,
                        discovered.len(),
                    );
                    continue;
                }

                let slots = MAX_DISCOVERY_CONNECTIONS - current_count;
                for dp in discovered.iter().take(slots) {
                    // SEC-FIX-3: Skip peers without a transport public key.
                    // Unsigned/unbound peers enable MITM via TOFU. On mainnet,
                    // only peers with verified transport PKs should be dialled.
                    if dp.transport_pubkey.is_none() {
                        debug!("Discovery: skip unsigned/unbound peer {}", dp.address);
                        continue;
                    }

                    let addr: SocketAddr = match dp.address.parse() {
                        Ok(a) => a,
                        Err(_) => {
                            debug!("Discovery: invalid addr '{}'", dp.address);
                            continue;
                        }
                    };

                    // SEC-C1: If the discovered peer has a known transport PK,
                    // use it for verified dial (MITM protection).
                    let expected_pk = dp.transport_pubkey.as_ref().and_then(|pk_bytes| {
                        ValidatorPqPublicKey::from_bytes(pk_bytes)
                            .map_err(|e| debug!("Discovery: bad pk for {}: {}", dp.address, e))
                            .ok()
                    });

                    match connect_to_peer(
                        addr,
                        &disc_pk,
                        &disc_sk,
                        expected_pk.as_ref(),
                        &disc_itx,
                        &disc_reg,
                        &disc_state,
                        chain_id,
                        &disc_node_name,
                        disc_node_mode,
                        listen_addr,
                        None,
                    )
                    .await
                    {
                        Ok(id) => info!("Discovery: connected to {} as {}", addr, id.short_hex(),),
                        Err(e) => debug!("Discovery: {} failed: {}", addr, e),
                    }
                }
            }
        });
    }

    // ── SEC-P2P-GUARD: Multi-layer inbound connection guard ──
    //
    // Replaces the previous SEC-H4 per-IP cooldown + simple inbound counter
    // with a comprehensive ConnectionGuard that provides:
    //
    //   1. Per-IP handshake throttling (MAX_HANDSHAKE_ATTEMPTS_PER_IP / 60s)
    //   2. Global half-open limit (MAX_HALF_OPEN with 15s timeout)
    //   3. /24 subnet diversity (MAX_INBOUND_PER_SUBNET)
    //   4. Per-IP saturation limit (MAX_INBOUND_PER_IP)
    //   5. Bogon IP rejection (is_bogon_ip)
    //
    // The guard is wrapped in Arc<Mutex<_>> for concurrent access from
    // the accept loop. Each inbound connection follows the lifecycle:
    //
    //   TCP accept → check_inbound(ip) → register_half_open(ip)
    //   → [handshake completes] → promote_to_established(slot_id)
    //   → [connection closes] → on_disconnect(ip)
    //
    use std::time::Duration;
    let conn_guard: Arc<tokio::sync::Mutex<misaka_p2p::ConnectionGuard>> = Arc::new(
        tokio::sync::Mutex::new(misaka_p2p::ConnectionGuard::with_config(guard_config)),
    );

    // Periodic cleanup of stale guard entries (half-open timeouts, throttle windows)
    {
        let guard = conn_guard.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;
                guard.lock().await.cleanup();
            }
        });
    }

    // Accept loop
    loop {
        match listener.accept().await {
            Ok((mut stream, addr)) => {
                let remote_ip = addr.ip();

                // ── SEC-P2P-GUARD: Pre-handshake admission check ──
                //
                // ALL checks (throttle, half-open, subnet, per-IP) are performed
                // BEFORE allocating any resources for this connection. If any check
                // fails, the TCP socket is dropped immediately.
                let slot_id = {
                    let mut guard = conn_guard.lock().await;

                    // Reject bogon IPs at the TCP level (defense in depth —
                    // PeerRecord validation also checks, but this catches direct
                    // connections that bypass discovery)
                    if reject_inbound_bogon_ip(&remote_ip, chain_id) {
                        debug!("SEC-P2P-GUARD: rejecting bogon IP {}", addr);
                        drop(stream);
                        continue;
                    }

                    match guard.check_inbound(remote_ip) {
                        misaka_p2p::GuardDecision::Allow => {
                            // All checks passed — allocate a half-open slot
                            guard.register_half_open(remote_ip)
                        }
                        misaka_p2p::GuardDecision::Reject(reason) => {
                            debug!("SEC-P2P-GUARD: rejecting {}: {}", addr, reason);
                            drop(stream);
                            continue;
                        }
                    }
                };

                let guard_clone = conn_guard.clone();
                let (pk, sk, itx, r, st, name, mode) = (
                    our_pk.clone(),
                    our_sk.clone(),
                    inbound_tx.clone(),
                    reg.clone(),
                    state.clone(),
                    node_name.clone(),
                    node_mode,
                );
                tokio::spawn(async move {
                    // Drop guard: on ANY exit path (success, handshake fail, peer disconnect),
                    // release the connection slot in the ConnectionGuard.
                    struct ConnSlotGuard {
                        guard: Arc<tokio::sync::Mutex<misaka_p2p::ConnectionGuard>>,
                        ip: std::net::IpAddr,
                        slot_id: u64,
                        promoted: bool,
                    }
                    impl Drop for ConnSlotGuard {
                        fn drop(&mut self) {
                            // We can't .await in Drop, so we spawn a blocking task.
                            // This is safe because the guard cleanup is fast (<1μs).
                            let guard = self.guard.clone();
                            let ip = self.ip;
                            let slot_id = self.slot_id;
                            let promoted = self.promoted;
                            tokio::spawn(async move {
                                let mut g = guard.lock().await;
                                if promoted {
                                    g.on_disconnect(ip);
                                } else {
                                    g.cancel_half_open(slot_id);
                                }
                            });
                        }
                    }
                    let mut slot_guard = ConnSlotGuard {
                        guard: guard_clone,
                        ip: remote_ip,
                        slot_id,
                        promoted: false,
                    };

                    // ── Handshake (while half-open slot is held) ──
                    let (hs, dk) = match tcp_responder_handshake(&mut stream, &pk, &sk, None).await {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("Handshake fail {}: {}", addr, e);
                            // slot_guard drop → cancel_half_open
                            return;
                        }
                    };

                    // ── Promote to established ──
                    {
                        let mut g = slot_guard.guard.lock().await;
                        g.promote_to_established(slot_id);
                    }
                    slot_guard.promoted = true;

                    let (established_count, half_open_count) = {
                        let g = slot_guard.guard.lock().await;
                        (g.established_count(), g.half_open_count())
                    };

                    let pid = derive_peer_id(&hs.peer_pk, chain_id);
                    info!(
                        "Peer {} auth (from {}) [guard: {} established, {} half-open]",
                        pid.short_hex(),
                        addr,
                        established_count,
                        half_open_count,
                    );
                    let (otx, orx) = mpsc::channel::<Vec<u8>>(PEER_OUTBOUND_CAPACITY);
                    r.write().await.insert(pid, otx);
                    if let Some(hello_bytes) =
                        initial_dag_hello_bytes(&st, chain_id, &name, mode, listen_addr).await
                    {
                        match r.read().await.peers.get(&pid).cloned() {
                            Some(tx) => {
                                if let Err(e) = tx.send(hello_bytes).await {
                                    warn!(
                                        "Failed to queue initial DAG hello for peer {}: {}",
                                        pid.short_hex(),
                                        e
                                    );
                                }
                            }
                            None => {
                                warn!(
                                    "Missing peer sender while queuing initial DAG hello for {}",
                                    pid.short_hex()
                                );
                            }
                        }
                    }
                    handle_peer(stream, pid, dk, itx, orx).await;
                    // slot_guard drop → on_disconnect(ip)
                    r.write().await.remove(&pid);
                });
            }
            Err(e) => {
                error!("Accept: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
    }
}
