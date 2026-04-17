// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Narwhal block relay transport over MISAKA's PQ-secure P2P primitives.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use misaka_crypto::validator_sig::{
    validator_sign, validator_verify, ValidatorPqPublicKey, ValidatorPqSecretKey,
    ValidatorPqSignature,
};
use misaka_p2p::handshake::{responder_handle, HandshakeResult, InitiatorHandshake};
use misaka_p2p::narwhal_block_relay::{
    NarwhalRelayMessage, VoteRateLimiter, MAX_VOTES_PER_PEER_PER_EPOCH,
};
use misaka_p2p::payload_type::MisakaMessage;
use misaka_p2p::secure_transport::{
    decrypt_frame, encode_wire_frame, AeadError, DirectionalKeys, NonceCounter, RecvNonceTracker,
    FRAME_HEADER_SIZE, MAX_FRAME_SIZE, NONCE_SIZE, TAG_SIZE,
};
use misaka_pqc::pq_kem::MlKemPublicKey;
use sha3::{Digest, Sha3_256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

const HANDSHAKE_TIMEOUT_SECS: u64 = 15;
const READ_TIMEOUT_SECS: u64 = 120;
const PEER_OUTBOUND_CAPACITY: usize = 256;
const MAINNET_CHAIN_ID: u32 = 1;

#[derive(Clone, Debug)]
pub struct RelayPeer {
    pub authority_index: u32,
    pub address: SocketAddr,
    pub public_key: ValidatorPqPublicKey,
    /// When true, this peer is always dialed outbound regardless of the
    /// `authority_index` ordering rule. Set for `--seeds`-derived peers
    /// so the node proactively connects to operator seeds even when their
    /// authority_index is lower than ours.
    pub force_dial: bool,
}

#[derive(Clone, Debug)]
pub struct NarwhalRelayTransportConfig {
    pub listen_addr: SocketAddr,
    pub chain_id: u32,
    pub authority_index: u32,
    pub public_key: ValidatorPqPublicKey,
    pub secret_key: Arc<ValidatorPqSecretKey>,
    pub peers: Vec<RelayPeer>,
    pub guard_config: misaka_p2p::GuardConfig,
    /// SEC-FIX v0.5.7: accept inbound connections from peers whose pubkey
    /// is NOT in the configured `peers` list. The connecting node is
    /// registered as a transient *observer*: it receives broadcasts but
    /// is never targeted by `ToAuthority` routing, and its messages
    /// arrive tagged with the synthetic `OBSERVER_SENTINEL_AUTHORITY`
    /// so consensus rejects any block it tries to propose. Operators
    /// enable this with `MISAKA_ACCEPT_OBSERVERS=1`.
    pub accept_observers: bool,
    /// SEC-FIX v0.5.7: this node is itself running as an observer (its
    /// validator.key fingerprint is not in the genesis committee). When
    /// true:
    ///   * the outbound-dial filter is bypassed so this node dials every
    ///     committee member instead of only those with `authority_index >
    ///     self.authority_index` (which would be empty for an observer
    ///     using a synthetic high authority_index);
    ///   * the listener still binds (so it can be debugged with curl /
    ///     local tools) but inbound peers are not expected.
    pub observer_self: bool,
}

/// Sentinel authority index used to tag inbound observer connections so
/// downstream consensus components can recognise (and ignore) them. It is
/// chosen to be far above any plausible committee size while still fitting
/// in `u32`, so accidental collisions with real authorities are impossible.
pub const OBSERVER_SENTINEL_AUTHORITY: u32 = u32::MAX - 1;

#[derive(Clone, Debug)]
pub enum OutboundNarwhalRelayEvent {
    Broadcast(NarwhalRelayMessage),
    ToAuthority {
        authority_index: u32,
        message: NarwhalRelayMessage,
    },
}

#[derive(Clone, Debug)]
pub enum InboundNarwhalRelayEvent {
    PeerConnected {
        authority_index: u32,
        peer_id: misaka_p2p::PeerId,
        address: SocketAddr,
        public_key: Option<Vec<u8>>,
    },
    PeerDisconnected {
        authority_index: u32,
        peer_id: misaka_p2p::PeerId,
        address: SocketAddr,
    },
    Message {
        authority_index: u32,
        peer_id: misaka_p2p::PeerId,
        address: SocketAddr,
        message: NarwhalRelayMessage,
    },
}

fn effective_guard_config(config: &NarwhalRelayTransportConfig) -> misaka_p2p::GuardConfig {
    let mut guard = config.guard_config.clone();
    let all_peers_loopback = !config.peers.is_empty()
        && config
            .peers
            .iter()
            .all(|peer| peer.address.ip().is_loopback());

    // Local multi-validator rehearsals often run every validator on the same
    // host and advertise 127.0.0.1:<port> inside the generated genesis. The
    // production inbound diversity guard is correct for public networks, but
    // it rejects same-IP committee members in that topology and prevents the
    // committee from fully meshing. Only relax the limits for explicit
    // non-mainnet, loopback-only committee topologies.
    if config.chain_id != MAINNET_CHAIN_ID && all_peers_loopback {
        let peer_budget = config.peers.len().saturating_add(1);
        guard.max_inbound_per_ip = guard.max_inbound_per_ip.max(peer_budget);
        guard.max_inbound_per_subnet = guard.max_inbound_per_subnet.max(peer_budget);
        guard.max_handshake_attempts_per_ip = guard
            .max_handshake_attempts_per_ip
            .max((peer_budget.saturating_mul(4)) as u32);
        guard.max_half_open = guard.max_half_open.max(peer_budget.saturating_mul(4));
    }

    guard
}

fn derive_peer_id(pk: &ValidatorPqPublicKey, chain_id: u32) -> misaka_p2p::PeerId {
    misaka_p2p::PeerId::from_pubkey(&pk.to_bytes(), chain_id)
}

fn reject_inbound_bogon_ip(ip: &IpAddr, chain_id: u32) -> bool {
    if chain_id != MAINNET_CHAIN_ID && ip.is_loopback() {
        return false;
    }
    misaka_p2p::is_bogon_ip(ip)
}

fn bypass_inbound_guard(ip: &IpAddr, chain_id: u32) -> bool {
    chain_id != MAINNET_CHAIN_ID && ip.is_loopback()
}

async fn read_fixed(stream: &mut TcpStream, n: usize, label: &str) -> Result<Vec<u8>, String> {
    let timeout = Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
    let mut buf = vec![0u8; n];
    tokio::time::timeout(timeout, stream.read_exact(&mut buf))
        .await
        .map_err(|_| format!("timeout: {label}"))?
        .map_err(|e| format!("I/O {label}: {e}"))?;
    Ok(buf)
}

async fn read_lp(stream: &mut TcpStream, max: usize, label: &str) -> Result<Vec<u8>, String> {
    let lb = read_fixed(stream, 4, &format!("{label} len")).await?;
    let len = u32::from_le_bytes([lb[0], lb[1], lb[2], lb[3]]) as usize;
    if len > max {
        return Err(format!("{label} too large: {len}"));
    }
    read_fixed(stream, len, label).await
}

async fn write_lp(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    stream
        .write_all(&(data.len() as u32).to_le_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(data).await.map_err(|e| e.to_string())
}

async fn tcp_responder_handshake(
    stream: &mut TcpStream,
    our_pk: &ValidatorPqPublicKey,
    our_sk: &ValidatorPqSecretKey,
) -> Result<(HandshakeResult, DirectionalKeys), String> {
    let kem_pk_buf = read_fixed(stream, 1184, "kem_pk").await?;
    let ephemeral_pk =
        MlKemPublicKey::from_bytes(&kem_pk_buf).map_err(|e| format!("bad kem pk: {e}"))?;

    let id_pk_buf = read_lp(stream, 8192, "init_pk").await?;
    let initiator_pk =
        ValidatorPqPublicKey::from_bytes(&id_pk_buf).map_err(|e| format!("bad init pk: {e}"))?;

    let nonce_i_buf = read_fixed(stream, 32, "nonce_i").await?;
    let mut nonce_i = [0u8; 32];
    nonce_i.copy_from_slice(&nonce_i_buf);

    let ver_buf = read_fixed(stream, 1, "version").await?;
    let initiator_version = ver_buf[0];

    let reply = responder_handle(
        &ephemeral_pk,
        &nonce_i,
        initiator_version,
        our_pk.clone(),
        our_sk,
    )
    .map_err(|e| format!("responder_handle: {e}"))?;

    stream
        .write_all(reply.ciphertext.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    write_lp(stream, &our_pk.to_bytes()).await?;
    write_lp(stream, &reply.responder_sig.to_bytes()).await?;
    stream
        .write_all(&reply.nonce_r)
        .await
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&[reply.protocol_version])
        .await
        .map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    let init_sig_buf = read_lp(stream, 8192, "init_sig").await?;
    let init_sig = ValidatorPqSignature::from_bytes(&init_sig_buf)
        .map_err(|e| format!("bad init sig: {e}"))?;

    let hs = reply
        .verify_initiator(&init_sig, &initiator_pk)
        .map_err(|e| format!("verify init: {e}"))?;

    let keys = DirectionalKeys::derive(&hs.session_key, false);
    Ok((hs, keys))
}

async fn tcp_initiator_handshake(
    stream: &mut TcpStream,
    our_pk: &ValidatorPqPublicKey,
    our_sk: &ValidatorPqSecretKey,
    expected_responder_pk: &ValidatorPqPublicKey,
) -> Result<(HandshakeResult, DirectionalKeys), String> {
    let hs = InitiatorHandshake::new(our_pk.clone()).map_err(|e| format!("kem keygen: {e}"))?;

    stream
        .write_all(hs.ephemeral_pk.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    write_lp(stream, &our_pk.to_bytes()).await?;
    stream
        .write_all(&hs.nonce_i)
        .await
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&[hs.protocol_version])
        .await
        .map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    let ct_buf = read_fixed(stream, 1088, "ct").await?;
    let ciphertext = misaka_pqc::pq_kem::MlKemCiphertext::from_bytes(&ct_buf)
        .map_err(|e| format!("bad ct: {e}"))?;

    let resp_pk_buf = read_lp(stream, 8192, "resp_pk").await?;
    let responder_pk =
        ValidatorPqPublicKey::from_bytes(&resp_pk_buf).map_err(|e| format!("bad resp pk: {e}"))?;
    if &responder_pk != expected_responder_pk {
        return Err(format!(
            "MITM: responder pk mismatch (expected {}, got {})",
            hex::encode(&expected_responder_pk.to_bytes()[..8]),
            hex::encode(&responder_pk.to_bytes()[..8]),
        ));
    }

    let resp_sig_buf = read_lp(stream, 8192, "resp_sig").await?;
    let responder_sig = ValidatorPqSignature::from_bytes(&resp_sig_buf)
        .map_err(|e| format!("bad resp sig: {e}"))?;

    let nonce_r_buf = read_fixed(stream, 32, "nonce_r").await?;
    let mut nonce_r = [0u8; 32];
    nonce_r.copy_from_slice(&nonce_r_buf);

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

    use misaka_pqc::pq_kem::{kdf_derive, ml_kem_decapsulate};
    let ss =
        ml_kem_decapsulate(&hs.ephemeral_sk, &ciphertext).map_err(|e| format!("decap: {e}"))?;
    let session_key = kdf_derive(&ss, b"MISAKA-v3:p2p:session-key:", 0);

    let ipk_hash: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA-v3:initiator-pk:");
        h.update(&ValidatorPqPublicKey::zero().to_bytes());
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

    validator_verify(&transcript, &responder_sig, &responder_pk)
        .map_err(|e| format!("resp sig verify: {e}"))?;

    let our_sig = validator_sign(&transcript, our_sk).map_err(|e| format!("sign: {e}"))?;
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

async fn read_raw_frame(reader: &mut tokio::io::ReadHalf<TcpStream>) -> Result<Vec<u8>, AeadError> {
    let mut len_buf = [0u8; FRAME_HEADER_SIZE];
    tokio::time::timeout(
        Duration::from_secs(READ_TIMEOUT_SECS),
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

/// Per-observer monotonic identifier. Observers are clients who are not
/// in the consensus committee but have been allowed to connect (when the
/// operator runs with `MISAKA_ACCEPT_OBSERVERS=1`). Each observer gets a
/// fresh `ObserverId` so multiple concurrent observers do not collide in
/// the registry the way they would if all keyed by `authority_index`.
type ObserverId = u64;

/// Tracks how a particular inbound peer was registered, so the post-session
/// cleanup uses the right key.
enum RegistryHandle {
    Validator,
    Observer(ObserverId),
}

static OBSERVER_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_observer_id() -> ObserverId {
    OBSERVER_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

struct PeerRegistry {
    peers: HashMap<u32, mpsc::Sender<MisakaMessage>>,
    observers: HashMap<ObserverId, mpsc::Sender<MisakaMessage>>,
}

impl PeerRegistry {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
            observers: HashMap::new(),
        }
    }

    fn insert(&mut self, authority_index: u32, tx: mpsc::Sender<MisakaMessage>) {
        self.peers.insert(authority_index, tx);
    }

    fn remove(&mut self, authority_index: u32) {
        self.peers.remove(&authority_index);
    }

    fn insert_observer(&mut self, id: ObserverId, tx: mpsc::Sender<MisakaMessage>) {
        self.observers.insert(id, tx);
    }

    fn remove_observer(&mut self, id: ObserverId) {
        self.observers.remove(&id);
    }

    async fn send(&self, authority_index: u32, msg: MisakaMessage) {
        if let Some(tx) = self.peers.get(&authority_index) {
            let _ = tx.send(msg).await;
        }
    }

    async fn broadcast(&self, msg: MisakaMessage) {
        // SEC-FIX v0.5.7: broadcast goes to BOTH committee peers and
        // observers. Observers receive the chain state read-only — they
        // cannot influence consensus because they are not in the
        // committee, so they have no stake and their `ToAuthority`
        // messages are never routed back through `send()`.
        for tx in self.peers.values() {
            let _ = tx.send(msg.clone()).await;
        }
        for tx in self.observers.values() {
            let _ = tx.send(msg.clone()).await;
        }
    }
}

async fn run_peer_session(
    stream: TcpStream,
    peer: RelayPeer,
    peer_id: misaka_p2p::PeerId,
    address: SocketAddr,
    keys: DirectionalKeys,
    inbound_tx: mpsc::Sender<InboundNarwhalRelayEvent>,
    mut peer_out_rx: mpsc::Receiver<MisakaMessage>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let short = peer_id.short_hex();
    let short_writer = short.clone();

    let writer_task = tokio::spawn(async move {
        let mut nonce = NonceCounter::new();
        while let Some(msg) = peer_out_rx.recv().await {
            let plaintext = match serde_json::to_vec(&msg) {
                Ok(bytes) => bytes,
                Err(err) => {
                    warn!(
                        "Failed to encode relay message for {}: {}",
                        short_writer, err
                    );
                    continue;
                }
            };
            let wire = match encode_wire_frame(&keys.send_key, &mut nonce, &plaintext) {
                Ok(wire) => wire,
                Err(err) => {
                    warn!(
                        "Failed to encrypt relay message for {}: {}",
                        short_writer, err
                    );
                    break;
                }
            };
            if writer.write_all(&wire).await.is_err() || writer.flush().await.is_err() {
                break;
            }
        }
    });

    // SEC-FIX NH-2: Wire VoteRateLimiter into the peer session decode path
    let mut vote_limiter = VoteRateLimiter::new(MAX_VOTES_PER_PEER_PER_EPOCH);
    let peer_id_bytes = peer_id.as_bytes().to_vec();

    // SEC-FIX TM-6/TM-7: Counters for disconnect thresholds
    const MAX_RATE_LIMIT_VIOLATIONS: u32 = 10;
    const MAX_CONSECUTIVE_DECODE_FAILURES: u32 = 20;
    let mut rate_limit_violations: u32 = 0;
    let mut decode_fail_count: u32 = 0;

    let mut recv_tracker = RecvNonceTracker::new();
    loop {
        let raw_frame = match read_raw_frame(&mut reader).await {
            Ok(frame) => frame,
            Err(AeadError::Io(err)) if err.contains("timeout") => break,
            Err(err) => {
                debug!("relay read ended for {}: {}", short, err);
                break;
            }
        };

        let nonce_value = match raw_frame.get(..8).and_then(|b| <[u8; 8]>::try_from(b).ok()) {
            Some(bytes) => u64::from_le_bytes(bytes),
            None => {
                warn!("relay frame from {} missing nonce prefix", short);
                break;
            }
        };
        if let Err(err) = recv_tracker.check_and_record(nonce_value) {
            warn!("relay nonce check failed for {}: {}", short, err);
            break;
        }

        let plaintext = match decrypt_frame(&keys.recv_key, &raw_frame) {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!("relay decrypt failed for {}: {}", short, err);
                break;
            }
        };

        let message: MisakaMessage = match serde_json::from_slice(&plaintext) {
            Ok(message) => message,
            Err(err) => {
                // SEC-FIX TM-7: Count consecutive decode failures and disconnect
                decode_fail_count += 1;
                warn!(
                    "relay envelope decode failed for {} ({}/{}): {}",
                    short, decode_fail_count, MAX_CONSECUTIVE_DECODE_FAILURES, err
                );
                if decode_fail_count >= MAX_CONSECUTIVE_DECODE_FAILURES {
                    warn!(
                        "too many consecutive decode failures for {} — disconnecting",
                        short
                    );
                    break;
                }
                continue;
            }
        };
        decode_fail_count = 0; // reset on successful decode

        // SEC-FIX NH-2: Use rate-limited decoder to prevent CommitVote flooding
        match NarwhalRelayMessage::from_message_rate_limited(
            &message,
            &mut vote_limiter,
            &peer_id_bytes,
            0, // epoch is reset by VoteRateLimiter::check on change
        ) {
            Ok(message) => {
                if inbound_tx
                    .send(InboundNarwhalRelayEvent::Message {
                        authority_index: peer.authority_index,
                        peer_id,
                        address,
                        message,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(misaka_p2p::narwhal_block_relay::NarwhalRelayDecodeError::RateLimited) => {
                // SEC-FIX TM-6: Count rate limit violations and disconnect persistent offenders
                rate_limit_violations += 1;
                warn!(
                    "CommitVote rate limited for peer {} ({}/{})",
                    short, rate_limit_violations, MAX_RATE_LIMIT_VIOLATIONS
                );
                if rate_limit_violations >= MAX_RATE_LIMIT_VIOLATIONS {
                    warn!(
                        "persistent rate limit violations from {} — disconnecting",
                        short
                    );
                    break;
                }
            }
            Err(err) => {
                warn!("relay payload decode failed for {}: {}", short, err);
            }
        }
    }

    writer_task.abort();
    let _ = inbound_tx
        .send(InboundNarwhalRelayEvent::PeerDisconnected {
            authority_index: peer.authority_index,
            peer_id,
            address,
        })
        .await;
}

async fn connect_outbound_peer(
    peer: RelayPeer,
    config: NarwhalRelayTransportConfig,
    registry: Arc<RwLock<PeerRegistry>>,
    inbound_tx: mpsc::Sender<InboundNarwhalRelayEvent>,
) {
    let retry_delay = Duration::from_secs(2);

    loop {
        match TcpStream::connect(peer.address).await {
            Ok(mut stream) => {
                match tcp_initiator_handshake(
                    &mut stream,
                    &config.public_key,
                    &config.secret_key,
                    &peer.public_key,
                )
                .await
                {
                    Ok((hs, keys)) => {
                        let peer_id = derive_peer_id(&hs.peer_pk, config.chain_id);
                        let (peer_tx, peer_rx) = mpsc::channel(PEER_OUTBOUND_CAPACITY);
                        registry.write().await.insert(peer.authority_index, peer_tx);
                        let _ = inbound_tx
                            .send(InboundNarwhalRelayEvent::PeerConnected {
                                authority_index: peer.authority_index,
                                peer_id,
                                address: peer.address,
                                public_key: None,
                            })
                            .await;
                        run_peer_session(
                            stream,
                            peer.clone(),
                            peer_id,
                            peer.address,
                            keys,
                            inbound_tx.clone(),
                            peer_rx,
                        )
                        .await;
                        registry.write().await.remove(peer.authority_index);
                    }
                    Err(err) => {
                        warn!(
                            "Narwhal relay outbound handshake failed (authority={}, addr={}): {}",
                            peer.authority_index, peer.address, err
                        );
                    }
                }
            }
            Err(err) => {
                debug!(
                    "Narwhal relay connect retry (authority={}, addr={}): {}",
                    peer.authority_index, peer.address, err
                );
            }
        }

        tokio::time::sleep(retry_delay).await;
    }
}

pub fn spawn_narwhal_block_relay_transport(
    config: NarwhalRelayTransportConfig,
    inbound_tx: mpsc::Sender<InboundNarwhalRelayEvent>,
    mut outbound_rx: mpsc::Receiver<OutboundNarwhalRelayEvent>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    spawn_narwhal_block_relay_transport_with_updates(config, inbound_tx, outbound_rx, None)
}

pub fn spawn_narwhal_block_relay_transport_with_updates(
    config: NarwhalRelayTransportConfig,
    inbound_tx: mpsc::Sender<InboundNarwhalRelayEvent>,
    mut outbound_rx: mpsc::Receiver<OutboundNarwhalRelayEvent>,
    relay_update_rx: Option<mpsc::Receiver<Vec<RelayPeer>>>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let std_listener = std::net::TcpListener::bind(config.listen_addr)?;
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    info!(
        "Narwhal relay transport listening on {} (authority={})",
        config.listen_addr, config.authority_index
    );

    Ok(tokio::spawn(async move {
        let registry = Arc::new(RwLock::new(PeerRegistry::new()));
        let peer_by_pk: Arc<RwLock<HashMap<Vec<u8>, RelayPeer>>> = Arc::new(RwLock::new(
            config
                .peers
                .iter()
                .cloned()
                .map(|peer| (peer.public_key.to_bytes(), peer))
                .collect(),
        ));

        let outbound_registry = registry.clone();
        tokio::spawn(async move {
            while let Some(event) = outbound_rx.recv().await {
                match event {
                    OutboundNarwhalRelayEvent::Broadcast(message) => {
                        if let Ok(wire) = message.to_message() {
                            outbound_registry.read().await.broadcast(wire).await;
                        }
                    }
                    OutboundNarwhalRelayEvent::ToAuthority {
                        authority_index,
                        message,
                    } => {
                        if let Ok(wire) = message.to_message() {
                            outbound_registry
                                .read()
                                .await
                                .send(authority_index, wire)
                                .await;
                        }
                    }
                }
            }
        });

        // SEC-FIX v0.5.7: dial filter has three bypass paths.
        //   1. `force_dial`: seed-derived peers (`--seeds`) are always
        //      dialed so that a validator behind NAT can reach the
        //      operator seed even when the seed's authority_index is
        //      lower than ours.
        //   2. `observer_self`: observer nodes dial every committee peer
        //      regardless of authority_index ordering.
        //   3. Default ordering rule (`peer.authority_index >
        //      self.authority_index`): prevents both sides of a pair
        //      from dialing each other simultaneously.
        for peer in config
            .peers
            .iter()
            .filter(|peer| peer.force_dial || config.observer_self || peer.authority_index > config.authority_index)
            .cloned()
        {
            let registry = registry.clone();
            let inbound_tx = inbound_tx.clone();
            let config = config.clone();
            tokio::spawn(async move {
                connect_outbound_peer(peer, config, registry, inbound_tx).await;
            });
        }

        // Dynamic peer updates: spawn new outbound connections for newly
        // registered validators without restarting the relay.
        if let Some(mut update_rx) = relay_update_rx {
            let known_indices: std::sync::Arc<tokio::sync::Mutex<std::collections::HashSet<u32>>> =
                std::sync::Arc::new(tokio::sync::Mutex::new(
                    config.peers.iter().map(|p| p.authority_index).collect(),
                ));
            let update_registry = registry.clone();
            let update_inbound_tx = inbound_tx.clone();
            let update_config = config.clone();
            let update_peer_by_pk = peer_by_pk.clone();
            tokio::spawn(async move {
                while let Some(new_peers) = update_rx.recv().await {
                    let mut known = known_indices.lock().await;
                    for peer in new_peers {
                        if known.contains(&peer.authority_index) {
                            continue;
                        }
                        info!(
                            "Hot-reload: dialing new validator {} at {}",
                            peer.authority_index, peer.address,
                        );
                        known.insert(peer.authority_index);
                        update_peer_by_pk
                            .write()
                            .await
                            .insert(peer.public_key.to_bytes(), peer.clone());
                        let reg = update_registry.clone();
                        let tx = update_inbound_tx.clone();
                        let cfg = update_config.clone();
                        tokio::spawn(async move {
                            connect_outbound_peer(peer, cfg, reg, tx).await;
                        });
                    }
                }
            });
        }

        let guard_config = effective_guard_config(&config);
        if guard_config.max_inbound_per_ip != config.guard_config.max_inbound_per_ip
            || guard_config.max_inbound_per_subnet != config.guard_config.max_inbound_per_subnet
            || guard_config.max_handshake_attempts_per_ip
                != config.guard_config.max_handshake_attempts_per_ip
            || guard_config.max_half_open != config.guard_config.max_half_open
        {
            info!(
                "Narwhal relay local loopback topology detected; relaxing inbound guard \
                 (per_ip={}, per_subnet={}, attempts_per_ip={}, half_open={})",
                guard_config.max_inbound_per_ip,
                guard_config.max_inbound_per_subnet,
                guard_config.max_handshake_attempts_per_ip,
                guard_config.max_half_open
            );
        }
        let conn_guard: Arc<tokio::sync::Mutex<misaka_p2p::ConnectionGuard>> = Arc::new(
            tokio::sync::Mutex::new(misaka_p2p::ConnectionGuard::with_config(guard_config)),
        );
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

        loop {
            match listener.accept().await {
                Ok((mut stream, address)) => {
                    let remote_ip = address.ip();
                    let slot_id = {
                        let mut guard = conn_guard.lock().await;
                        if reject_inbound_bogon_ip(&remote_ip, config.chain_id) {
                            debug!("Rejecting bogon Narwhal relay inbound {}", address);
                            drop(stream);
                            continue;
                        }
                        if bypass_inbound_guard(&remote_ip, config.chain_id) {
                            guard.register_half_open(remote_ip)
                        } else {
                            match guard.check_inbound(remote_ip) {
                                misaka_p2p::GuardDecision::Allow => {
                                    guard.register_half_open(remote_ip)
                                }
                                misaka_p2p::GuardDecision::Reject(reason) => {
                                    debug!(
                                        "Rejecting Narwhal relay inbound {}: {}",
                                        address, reason
                                    );
                                    drop(stream);
                                    continue;
                                }
                            }
                        }
                    };

                    let guard = conn_guard.clone();
                    let inbound_tx = inbound_tx.clone();
                    let registry = registry.clone();
                    let config = config.clone();
                    let peer_by_pk = peer_by_pk.clone();
                    tokio::spawn(async move {
                        struct ConnSlotGuard {
                            guard: Arc<tokio::sync::Mutex<misaka_p2p::ConnectionGuard>>,
                            ip: IpAddr,
                            slot_id: u64,
                            promoted: bool,
                        }

                        impl Drop for ConnSlotGuard {
                            fn drop(&mut self) {
                                let guard = self.guard.clone();
                                let ip = self.ip;
                                let slot_id = self.slot_id;
                                let promoted = self.promoted;
                                tokio::spawn(async move {
                                    let mut guard = guard.lock().await;
                                    if promoted {
                                        guard.on_disconnect(ip);
                                    } else {
                                        guard.cancel_half_open(slot_id);
                                    }
                                });
                            }
                        }

                        let mut slot_guard = ConnSlotGuard {
                            guard,
                            ip: remote_ip,
                            slot_id,
                            promoted: false,
                        };

                        let (hs, keys) = match tcp_responder_handshake(
                            &mut stream,
                            &config.public_key,
                            &config.secret_key,
                        )
                        .await
                        {
                            Ok(result) => result,
                            Err(err) => {
                                warn!(
                                    "Narwhal relay inbound handshake failed {}: {}",
                                    address, err
                                );
                                return;
                            }
                        };

                        {
                            let mut guard = slot_guard.guard.lock().await;
                            guard.promote_to_established(slot_id);
                        }
                        slot_guard.promoted = true;

                        // SEC-FIX v0.5.7: handle observer connections.
                        //
                        // Two-tier acceptance:
                        //   1. Pubkey is in the committee → register as
                        //      a normal validator peer (keyed by
                        //      authority_index).
                        //   2. Pubkey is unknown AND `accept_observers`
                        //      is true → register as a transient
                        //      observer (keyed by a fresh ObserverId).
                        //      Observer connections receive broadcasts
                        //      but are tagged with the synthetic
                        //      OBSERVER_SENTINEL_AUTHORITY so consensus
                        //      will reject any block they try to send.
                        //   3. Pubkey is unknown and observers are
                        //      disabled → reject (existing behaviour).
                        let peer_id = derive_peer_id(&hs.peer_pk, config.chain_id);
                        let (peer_tx, peer_rx) = mpsc::channel(PEER_OUTBOUND_CAPACITY);

                        let known_peer = peer_by_pk.read().await.get(&hs.peer_pk.to_bytes()).cloned();
                        let (peer_for_session, registry_handle) = match known_peer {
                            Some(peer) => {
                                registry.write().await.insert(peer.authority_index, peer_tx);
                                let _ = inbound_tx
                                    .send(InboundNarwhalRelayEvent::PeerConnected {
                                        authority_index: peer.authority_index,
                                        peer_id,
                                        address,
                                        public_key: None,
                                    })
                                    .await;
                                (peer, RegistryHandle::Validator)
                            }
                            None if config.accept_observers => {
                                let observer_id = next_observer_id();
                                registry.write().await.insert_observer(observer_id, peer_tx);
                                info!(
                                    "Accepted observer {} from {} (observer_id={})",
                                    peer_id.short_hex(),
                                    address,
                                    observer_id,
                                );
                                let synthetic_peer = RelayPeer {
                                    authority_index: OBSERVER_SENTINEL_AUTHORITY,
                                    address,
                                    public_key: hs.peer_pk.clone(),
                                    force_dial: false,
                                };
                                let _ = inbound_tx
                                    .send(InboundNarwhalRelayEvent::PeerConnected {
                                        authority_index: OBSERVER_SENTINEL_AUTHORITY,
                                        peer_id,
                                        address,
                                        public_key: Some(hs.peer_pk.to_bytes().to_vec()),
                                    })
                                    .await;
                                (synthetic_peer, RegistryHandle::Observer(observer_id))
                            }
                            None => {
                                warn!(
                                    "Rejecting unknown relay peer {} \
                                     (set MISAKA_ACCEPT_OBSERVERS=1 to allow)",
                                    address
                                );
                                return;
                            }
                        };

                        run_peer_session(
                            stream,
                            peer_for_session.clone(),
                            peer_id,
                            address,
                            keys,
                            inbound_tx.clone(),
                            peer_rx,
                        )
                        .await;
                        match registry_handle {
                            RegistryHandle::Validator => {
                                registry
                                    .write()
                                    .await
                                    .remove(peer_for_session.authority_index);
                            }
                            RegistryHandle::Observer(id) => {
                                registry.write().await.remove_observer(id);
                            }
                        }
                    });
                }
                Err(err) => {
                    error!("Narwhal relay accept failed: {}", err);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (ValidatorPqPublicKey, Arc<ValidatorPqSecretKey>) {
        let kp = misaka_crypto::validator_sig::generate_validator_keypair();
        (kp.public_key, Arc::new(kp.secret_key))
    }

    fn dummy_peer(authority_index: u32, port: u16) -> RelayPeer {
        RelayPeer {
            authority_index,
            address: SocketAddr::from(([127, 0, 0, 1], port)),
            public_key: keypair().0,
            force_dial: false,
        }
    }

    #[test]
    fn local_loopback_topology_relaxes_inbound_guard() {
        let (public_key, secret_key) = keypair();
        let config = NarwhalRelayTransportConfig {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 16110)),
            chain_id: 2,
            authority_index: 0,
            public_key,
            secret_key,
            peers: (1..15).map(|i| dummy_peer(i, 16110 + i as u16)).collect(),
            guard_config: misaka_p2p::GuardConfig::default(),
            accept_observers: false,
            observer_self: false,
        };

        let effective = effective_guard_config(&config);
        assert!(effective.max_inbound_per_ip >= config.peers.len() + 1);
        assert!(effective.max_inbound_per_subnet >= config.peers.len() + 1);
        assert!(effective.max_handshake_attempts_per_ip >= ((config.peers.len() + 1) * 4) as u32);
    }

    #[test]
    fn public_topology_keeps_default_guard() {
        let (public_key, secret_key) = keypair();
        let config = NarwhalRelayTransportConfig {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 16110)),
            chain_id: 2,
            authority_index: 0,
            public_key,
            secret_key,
            peers: vec![RelayPeer {
                authority_index: 1,
                address: "133.167.126.51:16110".parse().expect("addr"),
                public_key: keypair().0,
                force_dial: false,
            }],
            guard_config: misaka_p2p::GuardConfig::default(),
            accept_observers: true,
            observer_self: false,
        };

        let effective = effective_guard_config(&config);
        assert_eq!(
            effective.max_inbound_per_ip,
            config.guard_config.max_inbound_per_ip
        );
        assert_eq!(
            effective.max_inbound_per_subnet,
            config.guard_config.max_inbound_per_subnet
        );
        assert_eq!(
            effective.max_handshake_attempts_per_ip,
            config.guard_config.max_handshake_attempts_per_ip
        );
    }

    #[test]
    fn non_mainnet_loopback_bypasses_inbound_guard() {
        let loopback = IpAddr::from([127, 0, 0, 1]);
        assert!(bypass_inbound_guard(&loopback, 2));
        assert!(!bypass_inbound_guard(&loopback, MAINNET_CHAIN_ID));
    }

    #[test]
    fn spawn_transport_returns_bind_error_when_port_in_use() {
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("occupied listener");
        let listen_addr = occupied.local_addr().expect("occupied addr");
        let (public_key, secret_key) = keypair();
        let (inbound_tx, _inbound_rx) = mpsc::channel(1);
        let (_outbound_tx, outbound_rx) = mpsc::channel(1);
        let config = NarwhalRelayTransportConfig {
            listen_addr,
            chain_id: 2,
            authority_index: 0,
            public_key,
            secret_key,
            peers: vec![],
            guard_config: misaka_p2p::GuardConfig::default(),
            accept_observers: false,
            observer_self: false,
        };

        let result = spawn_narwhal_block_relay_transport(config, inbound_tx, outbound_rx);
        assert!(result.is_err(), "expected bind conflict to return Err");
    }
}
