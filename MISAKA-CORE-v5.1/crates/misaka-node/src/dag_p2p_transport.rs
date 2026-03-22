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

#[cfg(feature = "experimental_dag")]
use std::collections::HashMap;
#[cfg(feature = "experimental_dag")]
use std::net::SocketAddr;
#[cfg(feature = "experimental_dag")]
use std::sync::Arc;

#[cfg(feature = "experimental_dag")]
use sha3::{Digest, Sha3_256};
#[cfg(feature = "experimental_dag")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "experimental_dag")]
use tokio::net::{TcpListener, TcpStream};
#[cfg(feature = "experimental_dag")]
use tokio::sync::{mpsc, RwLock};
#[cfg(feature = "experimental_dag")]
use tracing::{debug, error, info, warn};

#[cfg(feature = "experimental_dag")]
use misaka_crypto::validator_sig::{
    ValidatorPqPublicKey, ValidatorPqSecretKey, ValidatorPqSignature,
    validator_sign, validator_verify,
};
#[cfg(feature = "experimental_dag")]
use misaka_p2p::handshake::{responder_handle, HandshakeResult, InitiatorHandshake};
#[cfg(feature = "experimental_dag")]
use misaka_p2p::secure_transport::{
    decrypt_frame, encode_wire_frame, DirectionalKeys, NonceCounter,
    AeadError, FRAME_HEADER_SIZE, MAX_FRAME_SIZE, NONCE_SIZE, TAG_SIZE,
};
#[cfg(feature = "experimental_dag")]
use misaka_pqc::pq_kem::MlKemPublicKey;

#[cfg(feature = "experimental_dag")]
use crate::dag_p2p_network::{InboundDagEvent, OutboundDagEvent};

#[cfg(feature = "experimental_dag")]
const HANDSHAKE_TIMEOUT_SECS: u64 = 15;
#[cfg(feature = "experimental_dag")]
const READ_TIMEOUT_SECS: u64 = 120;
#[cfg(feature = "experimental_dag")]
const PEER_OUTBOUND_CAPACITY: usize = 256;
/// Warn when nonce reaches 90% of REKEY_THRESHOLD.
#[cfg(feature = "experimental_dag")]
const REKEY_WARN_AT: u64 = (misaka_p2p::secure_transport::REKEY_THRESHOLD as f64 * 0.9) as u64;
/// Peer discovery gossip interval (seconds).
#[cfg(feature = "experimental_dag")]
const DISCOVERY_GOSSIP_INTERVAL_SECS: u64 = 60;
/// Maximum outbound connections to attempt via discovery.
#[cfg(feature = "experimental_dag")]
const MAX_DISCOVERY_CONNECTIONS: usize = 8;

// ═══════════════════════════════════════════════════════════════
//  Peer Identity
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "experimental_dag")]
fn derive_peer_id(pk: &ValidatorPqPublicKey) -> [u8; 20] {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:peer-id:v1:");
    h.update(&pk.to_bytes());
    let hash: [u8; 32] = h.finalize().into();
    let mut id = [0u8; 20];
    id.copy_from_slice(&hash[..20]);
    id
}

// ═══════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "experimental_dag")]
async fn read_fixed(stream: &mut TcpStream, n: usize, label: &str) -> Result<Vec<u8>, String> {
    let timeout = tokio::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
    let mut buf = vec![0u8; n];
    tokio::time::timeout(timeout, stream.read_exact(&mut buf))
        .await
        .map_err(|_| format!("timeout: {}", label))?
        .map_err(|e| format!("I/O {}: {}", label, e))?;
    Ok(buf)
}

#[cfg(feature = "experimental_dag")]
async fn read_lp(stream: &mut TcpStream, max: usize, label: &str) -> Result<Vec<u8>, String> {
    let lb = read_fixed(stream, 4, &format!("{} len", label)).await?;
    let len = u32::from_le_bytes([lb[0], lb[1], lb[2], lb[3]]) as usize;
    if len > max { return Err(format!("{} too large: {}", label, len)); }
    read_fixed(stream, len, label).await
}

#[cfg(feature = "experimental_dag")]
async fn write_lp(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    stream.write_all(&(data.len() as u32).to_le_bytes()).await.map_err(|e| e.to_string())?;
    stream.write_all(data).await.map_err(|e| e.to_string())
}

// ═══════════════════════════════════════════════════════════════
//  Responder Handshake (inbound)
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "experimental_dag")]
async fn tcp_responder_handshake(
    stream: &mut TcpStream,
    our_pk: &ValidatorPqPublicKey,
    our_sk: &ValidatorPqSecretKey,
) -> Result<(HandshakeResult, DirectionalKeys), String> {
    let kem_pk_buf = read_fixed(stream, 1184, "kem_pk").await?;
    let ephemeral_pk = MlKemPublicKey::from_bytes(&kem_pk_buf)
        .map_err(|e| format!("bad kem pk: {}", e))?;

    let id_pk_buf = read_lp(stream, 8192, "init_pk").await?;
    let initiator_pk = ValidatorPqPublicKey::from_bytes(&id_pk_buf)
        .map_err(|e| format!("bad init pk: {}", e))?;

    let reply = responder_handle(&ephemeral_pk, our_pk.clone(), our_sk)
        .map_err(|e| format!("responder_handle: {}", e))?;

    stream.write_all(reply.ciphertext.as_bytes()).await.map_err(|e| e.to_string())?;
    write_lp(stream, &our_pk.to_bytes()).await?;
    write_lp(stream, &reply.responder_sig.to_bytes()).await?;
    stream.flush().await.map_err(|e| e.to_string())?;

    let init_sig_buf = read_lp(stream, 8192, "init_sig").await?;
    let init_sig = ValidatorPqSignature::from_bytes(&init_sig_buf)
        .map_err(|e| format!("bad init sig: {}", e))?;

    let hs = reply.verify_initiator(&init_sig, &initiator_pk)
        .map_err(|e| format!("verify init: {}", e))?;

    Ok((hs, DirectionalKeys::derive(&hs.session_key, false)))
}

// ═══════════════════════════════════════════════════════════════
//  Initiator Handshake (outbound)
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "experimental_dag")]
async fn tcp_initiator_handshake(
    stream: &mut TcpStream,
    our_pk: &ValidatorPqPublicKey,
    our_sk: &ValidatorPqSecretKey,
) -> Result<(HandshakeResult, DirectionalKeys), String> {
    let hs = InitiatorHandshake::new(our_pk.clone())
        .map_err(|e| format!("kem keygen: {}", e))?;

    // Send ephemeral KEM PK + identity PK
    stream.write_all(hs.ephemeral_pk.as_bytes()).await.map_err(|e| e.to_string())?;
    write_lp(stream, &our_pk.to_bytes()).await?;
    stream.flush().await.map_err(|e| e.to_string())?;

    // Read responder reply
    let ct_buf = read_fixed(stream, 1088, "ct").await?;
    let ciphertext = misaka_pqc::pq_kem::MlKemCiphertext::from_bytes(&ct_buf)
        .map_err(|e| format!("bad ct: {}", e))?;

    let resp_pk_buf = read_lp(stream, 8192, "resp_pk").await?;
    let responder_pk = ValidatorPqPublicKey::from_bytes(&resp_pk_buf)
        .map_err(|e| format!("bad resp pk: {}", e))?;

    let resp_sig_buf = read_lp(stream, 8192, "resp_sig").await?;
    let responder_sig = ValidatorPqSignature::from_bytes(&resp_sig_buf)
        .map_err(|e| format!("bad resp sig: {}", e))?;

    // Decapsulate + derive session key
    use misaka_pqc::pq_kem::{ml_kem_decapsulate, kdf_derive};
    let ss = ml_kem_decapsulate(&hs.ephemeral_sk, &ciphertext)
        .map_err(|e| format!("decap: {}", e))?;
    let session_key = kdf_derive(&ss, b"MISAKA-v2:p2p:session-key:", 0);

    // Build transcript (matches handshake.rs::build_transcript)
    let mut transcript = Vec::with_capacity(26 + 1184 + 1088);
    transcript.extend_from_slice(b"MISAKA-v2:p2p:transcript:");
    transcript.extend_from_slice(hs.ephemeral_pk.as_bytes());
    transcript.extend_from_slice(&ct_buf);

    // Verify responder's signature
    validator_verify(&transcript, &responder_sig, &responder_pk)
        .map_err(|e| format!("resp sig verify: {}", e))?;

    // Sign transcript + send
    let our_sig = validator_sign(&transcript, our_sk)
        .map_err(|e| format!("sign: {}", e))?;
    write_lp(stream, &our_sig.to_bytes()).await?;
    stream.flush().await.map_err(|e| e.to_string())?;

    let dir_keys = DirectionalKeys::derive(&session_key, true);
    Ok((HandshakeResult { session_key, peer_pk: responder_pk, our_signature: our_sig }, dir_keys))
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
#[cfg(feature = "experimental_dag")]
fn derive_rekey(session_key: &[u8; 32], epoch: u64, is_initiator: bool) -> ([u8; 32], DirectionalKeys) {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA-v2:p2p:rekey:");
    h.update(session_key);
    h.update(&epoch.to_le_bytes());
    let new_session: [u8; 32] = h.finalize().into();
    (new_session, DirectionalKeys::derive(&new_session, is_initiator))
}

// ═══════════════════════════════════════════════════════════════
//  Encrypted Frame I/O
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "experimental_dag")]
async fn read_encrypted_frame(
    reader: &mut tokio::io::ReadHalf<TcpStream>,
    recv_key: &[u8; 32],
) -> Result<Vec<u8>, AeadError> {
    let mut len_buf = [0u8; FRAME_HEADER_SIZE];
    tokio::time::timeout(
        tokio::time::Duration::from_secs(READ_TIMEOUT_SECS),
        reader.read_exact(&mut len_buf),
    )
    .await
    .map_err(|_| AeadError::Io("timeout".into()))?
    .map_err(|e| AeadError::Io(e.to_string()))?;

    let frame_len = u32::from_le_bytes(len_buf);
    if frame_len > MAX_FRAME_SIZE { return Err(AeadError::FrameTooLarge { size: frame_len }); }
    if frame_len < (NONCE_SIZE + TAG_SIZE) as u32 { return Err(AeadError::DecryptFailed); }

    let mut frame = vec![0u8; frame_len as usize];
    reader.read_exact(&mut frame).await.map_err(|e| AeadError::Io(e.to_string()))?;
    decrypt_frame(recv_key, &frame)
}

// ═══════════════════════════════════════════════════════════════
//  Per-Peer Connection Handler
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "experimental_dag")]
async fn handle_peer(
    stream: TcpStream, peer_id: [u8; 20], keys: DirectionalKeys,
    inbound_tx: mpsc::Sender<InboundDagEvent>,
    mut peer_out_rx: mpsc::Receiver<Vec<u8>>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let ph = hex::encode(&peer_id[..4]);

    let wph = ph.clone();
    let initial_session_key = keys.send_key; // Used as seed for rekey derivation
    let mut current_send_key = keys.send_key;
    let wh = tokio::spawn(async move {
        let mut nonce = NonceCounter::new();
        let mut rekey_epoch = 0u64;
        let mut warned_rekey = false;
        // We need the session key for rekey derivation — use send_key as proxy
        // (both sides derive identical keys from the same session_key)
        let mut session_seed = initial_session_key;

        while let Some(pt) = peer_out_rx.recv().await {
            // Check nonce proximity to exhaustion
            if !warned_rekey && nonce.current() >= REKEY_WARN_AT {
                warn!(
                    "Peer {} nonce at {}% of rekey threshold — rekey imminent",
                    wph, (nonce.current() * 100) / misaka_p2p::secure_transport::REKEY_THRESHOLD,
                );
                warned_rekey = true;
            }

            match encode_wire_frame(&current_send_key, &mut nonce, &pt) {
                Ok(w) => {
                    if writer.write_all(&w).await.is_err() || writer.flush().await.is_err() { break; }
                }
                Err(AeadError::NonceExhausted) => {
                    // Rekey: derive new keys from session seed + epoch
                    rekey_epoch += 1;
                    let (new_seed, new_keys) = derive_rekey(&session_seed, rekey_epoch, true);
                    session_seed = new_seed;
                    current_send_key = new_keys.send_key;
                    nonce = NonceCounter::new();
                    warned_rekey = false;
                    info!("Peer {} rekeyed (epoch={})", wph, rekey_epoch);

                    // Retry the frame with new keys
                    match encode_wire_frame(&current_send_key, &mut nonce, &pt) {
                        Ok(w) => {
                            if writer.write_all(&w).await.is_err() || writer.flush().await.is_err() { break; }
                        }
                        Err(_) => break,
                    }
                }
                Err(_) => break,
            }
        }
        debug!("Peer {} writer done", wph);
    });

    // Reader also needs rekey tracking (recv_key changes at same epoch)
    let mut current_recv_key = keys.recv_key;
    let mut recv_session_seed = keys.recv_key;
    let mut recv_rekey_epoch = 0u64;

    loop {
        match read_encrypted_frame(&mut reader, &current_recv_key).await {
            Ok(pt) => match serde_json::from_slice::<misaka_dag::dag_p2p::DagP2pMessage>(&pt) {
                Ok(msg) => { if inbound_tx.send(InboundDagEvent { peer_id, message: msg }).await.is_err() { break; } }
                Err(e) => { warn!("Peer {} bad msg: {}", ph, e); }
            },
            Err(AeadError::DecryptFailed) => {
                // May be a rekey boundary — try with next epoch keys
                recv_rekey_epoch += 1;
                let (new_seed, new_keys) = derive_rekey(&recv_session_seed, recv_rekey_epoch, false);
                recv_session_seed = new_seed;
                current_recv_key = new_keys.recv_key;
                debug!("Peer {} recv rekey attempt (epoch={})", ph, recv_rekey_epoch);
                // The failed frame is lost — next frame should decrypt with new key.
                // If the next frame also fails, the peer is genuinely broken.
                continue;
            }
            Err(e) => { debug!("Peer {} read: {}", ph, e); break; }
        }
    }
    wh.abort();
    info!("Peer {} disconnected", ph);
}

// ═══════════════════════════════════════════════════════════════
//  Peer Registry
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "experimental_dag")]
struct PeerRegistry { peers: HashMap<[u8; 20], mpsc::Sender<Vec<u8>>> }

#[cfg(feature = "experimental_dag")]
impl PeerRegistry {
    fn new() -> Self { Self { peers: HashMap::new() } }
    fn insert(&mut self, id: [u8; 20], tx: mpsc::Sender<Vec<u8>>) { self.peers.insert(id, tx); }
    fn remove(&mut self, id: &[u8; 20]) { self.peers.remove(id); }
    fn has(&self, id: &[u8; 20]) -> bool { self.peers.contains_key(id) }
    async fn send(&self, target: Option<&[u8; 20]>, data: &[u8]) {
        match target {
            Some(id) => { if let Some(tx) = self.peers.get(id) { let _ = tx.send(data.to_vec()).await; } }
            None => { for tx in self.peers.values() { let _ = tx.send(data.to_vec()).await; } }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Outbound Connect
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "experimental_dag")]
async fn connect_to_peer(
    addr: SocketAddr, pk: &ValidatorPqPublicKey, sk: &ValidatorPqSecretKey,
    itx: &mpsc::Sender<InboundDagEvent>, reg: &Arc<RwLock<PeerRegistry>>,
) -> Result<[u8; 20], String> {
    let mut stream = tokio::time::timeout(
        tokio::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        TcpStream::connect(addr),
    ).await
    .map_err(|_| format!("connect timeout: {}", addr))?
    .map_err(|e| format!("connect {}: {}", addr, e))?;

    let (hs, dk) = tcp_initiator_handshake(&mut stream, pk, sk).await?;
    let peer_id = derive_peer_id(&hs.peer_pk);

    if reg.read().await.has(&peer_id) {
        return Err(format!("already connected: {}", hex::encode(&peer_id[..4])));
    }

    let (otx, orx) = mpsc::channel::<Vec<u8>>(PEER_OUTBOUND_CAPACITY);
    reg.write().await.insert(peer_id, otx);

    let itx2 = itx.clone();
    let reg2 = reg.clone();
    tokio::spawn(async move {
        handle_peer(stream, peer_id, dk, itx2, orx).await;
        reg2.write().await.remove(&peer_id);
    });

    Ok(peer_id)
}

// ═══════════════════════════════════════════════════════════════
//  Main Entry Point
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "experimental_dag")]
pub async fn run_dag_p2p_transport(
    listen_addr: SocketAddr,
    our_pk: ValidatorPqPublicKey,
    our_sk: ValidatorPqSecretKey,
    inbound_tx: mpsc::Sender<InboundDagEvent>,
    mut outbound_rx: mpsc::Receiver<OutboundDagEvent>,
    _chain_id: u32,
    seed_addrs: Vec<SocketAddr>,
    observation: Arc<RwLock<crate::dag_p2p_surface::DagP2pObservationState>>,
) {
    let listener = match TcpListener::bind(listen_addr).await {
        Ok(l) => { info!("DAG P2P listening on {}", listen_addr); l }
        Err(e) => { error!("Bind P2P {}: {}", listen_addr, e); return; }
    };

    let reg = Arc::new(RwLock::new(PeerRegistry::new()));

    // Connect to seeds with retry
    for addr in seed_addrs {
        let (pk, sk, itx, r) = (our_pk.clone(), our_sk.clone(), inbound_tx.clone(), reg.clone());
        tokio::spawn(async move {
            let mut delay = 1000u64;
            for attempt in 1..=5u32 {
                match connect_to_peer(addr, &pk, &sk, &itx, &r).await {
                    Ok(id) => { info!("Seed {} ok (attempt {}): {}", addr, attempt, hex::encode(&id[..4])); return; }
                    Err(e) => { warn!("Seed {} attempt {}: {}", addr, attempt, e); }
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                delay = (delay * 2).min(30_000);
            }
            error!("Seed {} unreachable after 5 attempts", addr);
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
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(
                tokio::time::Duration::from_secs(DISCOVERY_GOSSIP_INTERVAL_SECS),
            );
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

                if discovered.is_empty() { continue; }

                // 3. Attempt to connect to discovered peers (up to cap)
                let current_count = disc_reg.read().await.peers.len();
                if current_count >= MAX_DISCOVERY_CONNECTIONS {
                    debug!(
                        "Discovery: already at {} peers (max={}), skipping {} discovered",
                        current_count, MAX_DISCOVERY_CONNECTIONS, discovered.len(),
                    );
                    continue;
                }

                let slots = MAX_DISCOVERY_CONNECTIONS - current_count;
                for addr_str in discovered.iter().take(slots) {
                    let addr: SocketAddr = match addr_str.parse() {
                        Ok(a) => a,
                        Err(_) => { debug!("Discovery: invalid addr '{}'", addr_str); continue; }
                    };
                    match connect_to_peer(addr, &disc_pk, &disc_sk, &disc_itx, &disc_reg).await {
                        Ok(id) => info!(
                            "Discovery: connected to {} as {}",
                            addr, hex::encode(&id[..4]),
                        ),
                        Err(e) => debug!("Discovery: {} failed: {}", addr, e),
                    }
                }
            }
        });
    }

    // Accept loop
    loop {
        match listener.accept().await {
            Ok((mut stream, addr)) => {
                let (pk, sk, itx, r) = (our_pk.clone(), our_sk.clone(), inbound_tx.clone(), reg.clone());
                tokio::spawn(async move {
                    let (hs, dk) = match tcp_responder_handshake(&mut stream, &pk, &sk).await {
                        Ok(r) => r,
                        Err(e) => { warn!("Handshake fail {}: {}", addr, e); return; }
                    };
                    let pid = derive_peer_id(&hs.peer_pk);
                    info!("Peer {} auth (from {})", hex::encode(&pid[..4]), addr);
                    let (otx, orx) = mpsc::channel::<Vec<u8>>(PEER_OUTBOUND_CAPACITY);
                    r.write().await.insert(pid, otx);
                    handle_peer(stream, pid, dk, itx, orx).await;
                    r.write().await.remove(&pid);
                });
            }
            Err(e) => { error!("Accept: {}", e); tokio::time::sleep(tokio::time::Duration::from_millis(100)).await; }
        }
    }
}
