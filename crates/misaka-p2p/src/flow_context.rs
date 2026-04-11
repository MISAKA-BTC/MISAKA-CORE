//! # Flow Context — Shared State for All P2P Flows
//!
//! Kaspa-aligned context object shared across all protocol flows.
//! Contains:
//! - OrphanBlocksPool: blocks whose parents we haven't seen yet
//! - ProcessQueue: ordered queue of blocks awaiting consensus processing
//! - TransactionsSpread: dedup + relay tracker for mempool transactions
//! - BlockEventLogger: aggregated block acceptance logging
//!
//! All data structures are PQ-aware: block hashes use SHA3-256,
//! transaction IDs use the PQ-native hash, and all identity
//! comparisons use ML-DSA-65 public key fingerprints.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::info;

use crate::hub::Hub;
use crate::router::PeerKey;

// ═══════════════════════════════════════════════════════════════
//  Hash type alias (SHA3-256 throughout MISAKA)
// ═══════════════════════════════════════════════════════════════
pub type Hash = [u8; 32];
pub const ZERO_HASH: Hash = [0u8; 32];

// ═══════════════════════════════════════════════════════════════
//  Orphan Blocks Pool
// ═══════════════════════════════════════════════════════════════

/// Maximum orphan blocks to hold in memory.
///
/// Orphans are full blocks (header + body), so this must be bounded
/// to prevent memory exhaustion attacks.
pub const MAX_ORPHANS: usize = 1024;

/// Maximum missing roots to track per orphan.
pub const MAX_MISSING_ROOTS_PER_ORPHAN: usize = 64;

/// An orphan block waiting for its parents.
#[derive(Debug, Clone)]
pub struct OrphanBlock {
    /// The full block data (header + transactions).
    pub block_data: Vec<u8>,
    /// Block hash.
    pub hash: Hash,
    /// Parent hashes that we don't have yet.
    pub missing_parents: Vec<Hash>,
    /// Which peer sent us this block.
    pub source_peer: PeerKey,
    /// When we received it (for GC).
    pub received_at: Instant,
}

/// Output of orphan resolution: blocks that can now be processed.
#[derive(Debug)]
pub struct OrphanOutput {
    pub unorphaned_blocks: Vec<Vec<u8>>,
    pub unorphaned_count: usize,
}

/// Pool of orphan blocks whose parents haven't arrived yet.
pub struct OrphanBlocksPool {
    /// Map from block hash → orphan entry.
    orphans: HashMap<Hash, OrphanBlock>,
    /// Reverse index: missing_parent_hash → set of orphan hashes waiting for it.
    missing_index: HashMap<Hash, HashSet<Hash>>,
    /// Maximum pool size.
    max_size: usize,
}

impl OrphanBlocksPool {
    pub fn new(max_size: usize) -> Self {
        Self {
            orphans: HashMap::with_capacity(max_size),
            missing_index: HashMap::new(),
            max_size,
        }
    }

    /// Add an orphan block. Returns `true` if added, `false` if duplicate or pool full.
    pub fn add(
        &mut self,
        hash: Hash,
        block_data: Vec<u8>,
        missing_parents: Vec<Hash>,
        source_peer: PeerKey,
    ) -> bool {
        if self.orphans.contains_key(&hash) {
            return false;
        }

        // Evict oldest if full.
        if self.orphans.len() >= self.max_size {
            self.evict_oldest();
        }

        let missing = missing_parents
            .iter()
            .take(MAX_MISSING_ROOTS_PER_ORPHAN)
            .copied()
            .collect::<Vec<_>>();

        for parent in &missing {
            self.missing_index.entry(*parent).or_default().insert(hash);
        }

        self.orphans.insert(
            hash,
            OrphanBlock {
                block_data,
                hash,
                missing_parents: missing,
                source_peer,
                received_at: Instant::now(),
            },
        );

        true
    }

    /// Try to resolve orphans when a new block with `resolved_hash` arrives.
    ///
    /// Returns all blocks that are now fully resolved (all parents present).
    pub fn resolve(&mut self, resolved_hash: &Hash) -> OrphanOutput {
        let waiting = match self.missing_index.remove(resolved_hash) {
            Some(set) => set,
            None => {
                return OrphanOutput {
                    unorphaned_blocks: vec![],
                    unorphaned_count: 0,
                }
            }
        };

        let mut unorphaned = Vec::new();

        for orphan_hash in waiting {
            if let Some(orphan) = self.orphans.get_mut(&orphan_hash) {
                orphan.missing_parents.retain(|p| p != resolved_hash);
                if orphan.missing_parents.is_empty() {
                    if let Some(removed) = self.orphans.remove(&orphan_hash) {
                        unorphaned.push(removed.block_data);
                    }
                }
            }
        }

        let count = unorphaned.len();
        OrphanOutput {
            unorphaned_blocks: unorphaned,
            unorphaned_count: count,
        }
    }

    /// Get all missing root hashes across all orphans (for requesting from peers).
    pub fn all_missing_roots(&self) -> Vec<Hash> {
        self.missing_index.keys().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.orphans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.orphans.is_empty()
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        self.orphans.contains_key(hash)
    }

    fn evict_oldest(&mut self) {
        if let Some(oldest_hash) = self
            .orphans
            .values()
            .min_by_key(|o| o.received_at)
            .map(|o| o.hash)
        {
            self.remove(&oldest_hash);
        }
    }

    fn remove(&mut self, hash: &Hash) {
        if let Some(orphan) = self.orphans.remove(hash) {
            for parent in &orphan.missing_parents {
                if let Some(set) = self.missing_index.get_mut(parent) {
                    set.remove(hash);
                    if set.is_empty() {
                        self.missing_index.remove(parent);
                    }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Process Queue
// ═══════════════════════════════════════════════════════════════

/// Maximum blocks in the process queue.
pub const MAX_PROCESS_QUEUE: usize = 8192;

/// Ordered queue of blocks awaiting consensus validation.
///
/// Blocks are inserted in topological order (parents before children)
/// to maximize parallel validation opportunities.
pub struct ProcessQueue {
    queue: VecDeque<ProcessQueueEntry>,
    seen: HashSet<Hash>,
    max_size: usize,
}

#[derive(Debug, Clone)]
pub struct ProcessQueueEntry {
    pub hash: Hash,
    pub block_data: Vec<u8>,
    pub source_peer: PeerKey,
    pub enqueued_at: Instant,
}

impl ProcessQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(max_size.min(1024)),
            seen: HashSet::with_capacity(max_size.min(1024)),
            max_size,
        }
    }

    /// Push a block to the back of the queue.
    /// Returns `false` if duplicate or queue full.
    pub fn push(&mut self, hash: Hash, block_data: Vec<u8>, source: PeerKey) -> bool {
        if self.seen.contains(&hash) || self.queue.len() >= self.max_size {
            return false;
        }
        self.seen.insert(hash);
        self.queue.push_back(ProcessQueueEntry {
            hash,
            block_data,
            source_peer: source,
            enqueued_at: Instant::now(),
        });
        true
    }

    /// Pop the next block to process.
    pub fn pop(&mut self) -> Option<ProcessQueueEntry> {
        let entry = self.queue.pop_front()?;
        self.seen.remove(&entry.hash);
        Some(entry)
    }

    /// Drain up to `n` entries.
    pub fn drain_batch(&mut self, n: usize) -> Vec<ProcessQueueEntry> {
        let count = n.min(self.queue.len());
        let batch: Vec<_> = self.queue.drain(..count).collect();
        for entry in &batch {
            self.seen.remove(&entry.hash);
        }
        batch
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        self.seen.contains(hash)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Transactions Spread
// ═══════════════════════════════════════════════════════════════

/// Maximum tracked transaction IDs for deduplication.
const MAX_TX_TRACK: usize = 65_536;

/// Tracks which peers have seen which transactions to avoid redundant relay.
pub struct TransactionsSpread {
    /// tx_id → set of peers who have announced or sent this tx.
    known_by: HashMap<Hash, HashSet<PeerKey>>,
    /// Ordered insertion for LRU eviction.
    order: VecDeque<Hash>,
    max_tracked: usize,
}

impl TransactionsSpread {
    pub fn new() -> Self {
        Self {
            known_by: HashMap::with_capacity(1024),
            order: VecDeque::with_capacity(1024),
            max_tracked: MAX_TX_TRACK,
        }
    }

    /// Record that a peer knows about a transaction.
    pub fn add(&mut self, tx_id: Hash, peer: PeerKey) {
        if !self.known_by.contains_key(&tx_id) {
            if self.order.len() >= self.max_tracked {
                if let Some(old) = self.order.pop_front() {
                    self.known_by.remove(&old);
                }
            }
            self.order.push_back(tx_id);
        }
        self.known_by.entry(tx_id).or_default().insert(peer);
    }

    /// Get the set of peers that DON'T know about this transaction yet.
    ///
    /// Used to determine who to relay to.
    pub fn peers_not_knowing(&self, tx_id: &Hash, all_peers: &[PeerKey]) -> Vec<PeerKey> {
        let known = self.known_by.get(tx_id);
        all_peers
            .iter()
            .filter(|pk| known.map_or(true, |set| !set.contains(pk)))
            .copied()
            .collect()
    }

    pub fn is_known_by(&self, tx_id: &Hash, peer: &PeerKey) -> bool {
        self.known_by
            .get(tx_id)
            .map_or(false, |set| set.contains(peer))
    }

    pub fn tracked_count(&self) -> usize {
        self.known_by.len()
    }
}

impl Default for TransactionsSpread {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Block Event Logger
// ═══════════════════════════════════════════════════════════════

/// Aggregated block acceptance events for structured logging.
#[derive(Debug, PartialEq)]
pub enum BlockLogEvent {
    /// Block accepted via relay from a peer.
    Relay(Hash),
    /// Block accepted via submit_block RPC.
    Submit(Hash),
    /// Block orphaned with N missing roots.
    Orphaned(Hash, usize),
    /// N blocks unorphaned (hash is a representative).
    Unorphaned(Hash, usize),
}

/// Collects block events and logs them in batches for readability.
pub struct BlockEventLogger {
    sender: tokio::sync::mpsc::Sender<BlockLogEvent>,
    _receiver_handle: Option<tokio::task::JoinHandle<()>>,
}

const BLOCK_EVENT_CHANNEL_CAPACITY: usize = 4096;

impl BlockEventLogger {
    /// Create and start the logger. Events are batched every `interval`.
    pub fn start(bps: usize) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<BlockLogEvent>(BLOCK_EVENT_CHANNEL_CAPACITY);
        let chunk_limit = bps.max(1) * 10;

        let handle = tokio::spawn(async move {
            let mut batch = Vec::with_capacity(chunk_limit);
            let mut interval = tokio::time::interval(Duration::from_secs(1));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            Self::flush_batch(&batch);
                            batch.clear();
                        }
                    }
                    event = rx.recv() => match event {
                        Some(ev) => {
                            batch.push(ev);
                            if batch.len() >= chunk_limit {
                                Self::flush_batch(&batch);
                                batch.clear();
                            }
                        }
                        None => break,
                    }
                }
            }
        });

        Self {
            sender: tx,
            _receiver_handle: Some(handle),
        }
    }

    pub fn log(&self, event: BlockLogEvent) {
        let _ = self.sender.try_send(event);
    }

    fn flush_batch(batch: &[BlockLogEvent]) {
        let mut relay_count = 0usize;
        let mut submit_count = 0usize;
        let mut orphan_count = 0usize;
        let mut unorphan_count = 0usize;
        let mut relay_rep: Option<Hash> = None;
        let mut submit_rep: Option<Hash> = None;

        for ev in batch {
            match ev {
                BlockLogEvent::Relay(h) => {
                    relay_count += 1;
                    relay_rep = Some(*h);
                }
                BlockLogEvent::Submit(h) => {
                    submit_count += 1;
                    submit_rep = Some(*h);
                }
                BlockLogEvent::Orphaned(_, roots) => {
                    orphan_count += 1;
                    let _ = roots; // Could aggregate
                }
                BlockLogEvent::Unorphaned(_, n) => {
                    unorphan_count += *n;
                }
            }
        }

        let total = relay_count + submit_count;
        if total > 0 {
            let rep = submit_rep.or(relay_rep).unwrap_or(ZERO_HASH);
            info!(
                "Accepted {} blocks (relay={}, submit={}) ...{}",
                total,
                relay_count,
                submit_count,
                hex::encode(&rep[..4])
            );
        }
        if orphan_count > 0 {
            info!("Orphaned {} block(s)", orphan_count);
        }
        if unorphan_count > 0 {
            info!("Unorphaned {} block(s)", unorphan_count);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Flow Context
// ═══════════════════════════════════════════════════════════════

/// Network configuration for the flow context.
#[derive(Debug, Clone)]
pub struct FlowConfig {
    /// Blocks per second target for this network.
    pub bps: usize,
    /// Chain ID (network identifier).
    pub chain_id: u32,
    /// Protocol version.
    pub protocol_version: u32,
    /// Maximum outbound connections.
    pub max_outbound: usize,
    /// Maximum inbound connections.
    pub max_inbound: usize,
    /// Node user agent string.
    pub user_agent: String,
    /// Whether this node is archival (serves full history).
    pub is_archival: bool,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            bps: 1,
            chain_id: 0,
            protocol_version: 3,
            max_outbound: 16,
            max_inbound: 48,
            user_agent: "misaka-node/0.5".into(),
            is_archival: false,
        }
    }
}

/// Shared context for all P2P protocol flows.
///
/// This is the MISAKA equivalent of Kaspa's `FlowContext`.
/// Every flow (block relay, tx relay, IBD, ping, address) receives
/// an `Arc<FlowContext>` and uses it to coordinate state.
/// Mempool access trait — allows P2P layer to read/write the transaction pool.
///
/// Implemented by the node's mempool to bridge P2P ↔ consensus.
pub trait MempoolAccess: Send + Sync {
    /// Look up a transaction by hash. Returns serialized TX bytes if found.
    fn get_transaction(&self, hash: &Hash) -> Option<Vec<u8>>;
    /// Insert a validated transaction. Returns true if newly inserted.
    fn insert_transaction(&self, hash: Hash, data: Vec<u8>) -> bool;
    /// Check if a transaction is already known.
    fn contains(&self, hash: &Hash) -> bool;
    /// Validate and insert a transaction into the mempool.
    ///
    /// Returns Ok(true) if newly inserted, Ok(false) if already known,
    /// Err(reason) if the transaction is invalid and should be rejected.
    ///
    /// Implementors MUST perform:
    /// 1. Structural validation (non-empty, size limit)
    /// 2. ML-DSA-65 signature verification on all spending keys
    /// 3. UTXO availability check (no double-spend)
    /// 4. Fee sufficiency check
    ///
    /// There is intentionally NO default implementation: every implementor
    /// must explicitly handle validation. A missing impl is a compile error.
    fn validate_and_insert(&self, hash: Hash, data: Vec<u8>) -> Result<bool, String>;
}

/// No-op mempool — test only. Cannot exist in production binary.
///
/// Phase 24 fix: #[cfg(test)] prevents accidental production use.
/// Production code MUST use FlowContext::with_mempool() with a real
/// MempoolAccess implementation.
#[cfg(test)]
pub struct NoOpMempool;
#[cfg(test)]
impl MempoolAccess for NoOpMempool {
    fn get_transaction(&self, _: &Hash) -> Option<Vec<u8>> {
        None
    }
    fn insert_transaction(&self, _: Hash, _: Vec<u8>) -> bool {
        false
    }
    fn contains(&self, _: &Hash) -> bool {
        false
    }
    fn validate_and_insert(&self, _: Hash, _: Vec<u8>) -> Result<bool, String> {
        Ok(false)
    }
}

pub struct FlowContext {
    /// Network configuration.
    pub config: FlowConfig,

    /// Central peer hub.
    pub hub: Hub,

    /// Orphan block pool.
    pub orphans: Mutex<OrphanBlocksPool>,

    /// Block processing queue.
    pub process_queue: Mutex<ProcessQueue>,

    /// Transaction relay dedup tracker.
    pub tx_spread: Mutex<TransactionsSpread>,

    /// Mempool access — for TX relay (P0-2 fix).
    pub mempool: Arc<dyn MempoolAccess>,

    /// Block acceptance event logger.
    pub block_logger: BlockEventLogger,

    /// Whether IBD is currently in progress.
    pub is_ibd_running: AtomicBool,

    /// Current virtual (selected parent) blue score.
    pub virtual_blue_score: AtomicU64,

    /// Timestamp of the last block accepted.
    pub last_block_accepted_at: Mutex<Instant>,
}

impl FlowContext {
    /// Test-only constructor with NoOpMempool.
    /// Production MUST use `with_mempool()` with a real MempoolAccess.
    #[cfg(test)]
    pub fn new(config: FlowConfig, hub: Hub) -> Arc<Self> {
        Self::with_mempool(config, hub, Arc::new(NoOpMempool))
    }

    pub fn with_mempool(
        config: FlowConfig,
        hub: Hub,
        mempool: Arc<dyn MempoolAccess>,
    ) -> Arc<Self> {
        let bps = config.bps;
        Arc::new(Self {
            config,
            hub,
            orphans: Mutex::new(OrphanBlocksPool::new(MAX_ORPHANS)),
            process_queue: Mutex::new(ProcessQueue::new(MAX_PROCESS_QUEUE)),
            tx_spread: Mutex::new(TransactionsSpread::new()),
            mempool,
            block_logger: BlockEventLogger::start(bps),
            is_ibd_running: AtomicBool::new(false),
            virtual_blue_score: AtomicU64::new(0),
            last_block_accepted_at: Mutex::new(Instant::now()),
        })
    }

    /// Check if we should enter IBD mode based on our blue score vs. the peer's.
    pub fn should_start_ibd(&self, peer_blue_score: u64) -> bool {
        let our_score = self.virtual_blue_score.load(Ordering::Relaxed);
        // If peer is significantly ahead, we need IBD.
        peer_blue_score > our_score + (self.config.bps as u64 * 60)
    }

    /// Whether IBD is currently running.
    pub fn is_ibd(&self) -> bool {
        self.is_ibd_running.load(Ordering::Relaxed)
    }

    /// Set IBD running state.
    pub fn set_ibd(&self, running: bool) {
        self.is_ibd_running.store(running, Ordering::Relaxed);
    }

    /// Update the virtual blue score.
    pub fn update_blue_score(&self, score: u64) {
        self.virtual_blue_score.store(score, Ordering::Relaxed);
    }

    /// Record that a block was accepted.
    pub fn on_block_accepted(&self) {
        *self.last_block_accepted_at.lock() = Instant::now();
    }

    /// How long since the last block was accepted.
    pub fn time_since_last_block(&self) -> Duration {
        self.last_block_accepted_at.lock().elapsed()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests — Phase 24: MempoolAccess safety
// ═══════════════════════════════════════════════════════════════
#[cfg(test)]
mod mempool_access_tests {
    use super::*;

    /// Verify NoOpMempool rejects nothing (returns Ok(false) for everything).
    /// This is acceptable because NoOpMempool is #[cfg(test)] only.
    #[test]
    fn noop_mempool_validate_and_insert_returns_false() {
        let noop = NoOpMempool;
        let hash = [0xAA; 32];
        let data = vec![1, 2, 3];
        assert_eq!(noop.validate_and_insert(hash, data).unwrap(), false);
    }

    /// Verify NoOpMempool never stores anything.
    #[test]
    fn noop_mempool_contains_always_false() {
        let noop = NoOpMempool;
        let hash = [0xBB; 32];
        noop.insert_transaction(hash, vec![1, 2, 3]);
        assert!(!noop.contains(&hash));
    }

    /// A real MempoolAccess impl that rejects unsigned transactions.
    /// Demonstrates the trait forces explicit validate_and_insert impl.
    struct StrictMempool;
    impl MempoolAccess for StrictMempool {
        fn get_transaction(&self, _: &Hash) -> Option<Vec<u8>> {
            None
        }
        fn insert_transaction(&self, _: Hash, _: Vec<u8>) -> bool {
            false
        }
        fn contains(&self, _: &Hash) -> bool {
            false
        }
        fn validate_and_insert(&self, _: Hash, data: Vec<u8>) -> Result<bool, String> {
            if data.is_empty() {
                return Err("empty transaction".into());
            }
            if data.len() > 1_048_576 {
                return Err("oversized transaction".into());
            }
            // Require minimum payload (structural check placeholder).
            if data.len() < 64 {
                return Err("transaction too small to contain valid signature".into());
            }
            Ok(true)
        }
    }

    #[test]
    fn strict_mempool_rejects_empty_tx() {
        let mp = StrictMempool;
        assert!(mp.validate_and_insert([0; 32], vec![]).is_err());
    }

    #[test]
    fn strict_mempool_rejects_oversized_tx() {
        let mp = StrictMempool;
        let big = vec![0u8; 2_000_000];
        assert!(mp.validate_and_insert([0; 32], big).is_err());
    }

    #[test]
    fn strict_mempool_rejects_too_small_tx() {
        let mp = StrictMempool;
        assert!(mp.validate_and_insert([0; 32], vec![1; 10]).is_err());
    }

    #[test]
    fn strict_mempool_accepts_valid_size_tx() {
        let mp = StrictMempool;
        assert!(mp.validate_and_insert([0; 32], vec![1; 100]).unwrap());
    }
}
