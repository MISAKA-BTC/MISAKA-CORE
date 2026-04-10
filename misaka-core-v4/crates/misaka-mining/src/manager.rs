//! Mining manager: coordinates mempool, template building, and caching.

use crate::block_template::builder::BlockTemplateBuilder;
use crate::block_template::policy::BlockPolicy;
use crate::block_template::{BlockTemplate, CoinbaseData, TemplateTransaction};
use crate::cache::BlockTemplateCache;
use crate::errors::MiningResult;
use crate::fee_rate::{FeeEstimateVerbose, FeeRateEstimator, FeerateEstimations};
use crate::mempool::config::MempoolConfig;
use crate::mempool::handle_new_block::handle_new_block_transactions;
use crate::mempool::model::tx::MempoolTransaction;
use crate::mempool::tx::{Orphan, Priority, RbfPolicy};
use crate::mempool::validate_and_insert::validate_and_insert_transaction;
use crate::mempool::{Mempool, MempoolStats};
use crate::model::tx_insert::TransactionInsertion;
use crate::model::{MiningCounters, MiningCountersSnapshot};

use parking_lot::RwLock;
use std::sync::Arc;

/// Main mining manager that coordinates all block production activities.
pub struct MiningManager {
    config: Arc<MempoolConfig>,
    block_policy: BlockPolicy,
    mempool: RwLock<Mempool>,
    template_cache: BlockTemplateCache,
    fee_estimator: RwLock<FeeRateEstimator>,
    counters: Arc<MiningCounters>,
}

impl MiningManager {
    pub fn new(
        target_time_per_block: u64,
        relay_non_std: bool,
        max_block_mass: u64,
        cache_lifetime: Option<u64>,
        counters: Arc<MiningCounters>,
    ) -> Self {
        let config =
            MempoolConfig::build_default(target_time_per_block, relay_non_std, max_block_mass);
        Self::with_config(config, cache_lifetime, counters)
    }

    pub fn with_config(
        config: MempoolConfig,
        cache_lifetime: Option<u64>,
        counters: Arc<MiningCounters>,
    ) -> Self {
        let config = Arc::new(config);
        let block_policy = BlockPolicy {
            max_block_mass: config.max_block_mass,
            ..Default::default()
        };
        Self {
            mempool: RwLock::new(Mempool::new(config.clone(), counters.clone())),
            template_cache: BlockTemplateCache::new(cache_lifetime),
            fee_estimator: RwLock::new(FeeRateEstimator::new(100, config.minimum_fee_rate)),
            config,
            block_policy,
            counters,
        }
    }

    /// Get a block template, using cache if available.
    pub fn get_block_template(
        &self,
        virtual_state_id: u64,
        parent_hashes: Vec<[u8; 32]>,
        daa_score: u64,
        timestamp: u64,
        bits: u32,
        coinbase: CoinbaseData,
    ) -> MiningResult<BlockTemplate> {
        // Check cache
        let mut cache_lock = self.template_cache.lock(virtual_state_id);
        if let Some(cached) = cache_lock.get_immutable_cached_template() {
            self.counters
                .cache_hits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if cached.coinbase_data.validator_script == coinbase.validator_script {
                return Ok((*cached).clone());
            }
            return Ok(BlockTemplateBuilder::modify_coinbase(&cached, coinbase));
        }

        self.counters
            .cache_misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.counters
            .template_builds
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Select transactions from mempool
        let mempool = self.mempool.read();
        let selected_ids = mempool.select_transactions(self.block_policy.max_block_mass);

        let transactions: Vec<TemplateTransaction> = selected_ids
            .iter()
            .filter_map(|id| {
                mempool.get(id).map(|tx| TemplateTransaction {
                    tx_id: tx.tx_id,
                    raw_data: tx.raw_data.clone(),
                    mass: tx.mass,
                    fee: tx.fee,
                })
            })
            .collect();
        drop(mempool);

        let builder = BlockTemplateBuilder::new(self.block_policy.clone());
        let template = builder.build(
            parent_hashes,
            daa_score,
            timestamp,
            bits,
            coinbase,
            transactions,
        )?;

        cache_lock.set_template(template.clone());
        Ok(template)
    }

    /// Submit a new transaction to the mempool.
    pub fn submit_transaction(
        &self,
        tx: MempoolTransaction,
        orphan_policy: Orphan,
        priority: Priority,
        rbf_policy: RbfPolicy,
    ) -> MiningResult<TransactionInsertion> {
        let mut mempool = self.mempool.write();
        validate_and_insert_transaction(&mut mempool, tx, orphan_policy, priority, rbf_policy)
    }

    /// Handle a newly accepted block by removing its transactions.
    pub fn handle_new_block(&self, block_tx_ids: &[[u8; 32]], fee_rates: &[f64], total_mass: u64) {
        let removed = {
            let mut mempool = self.mempool.write();
            handle_new_block_transactions(&mut mempool, block_tx_ids)
        };
        self.counters
            .block_tx_counts
            .fetch_add(removed as u64, std::sync::atomic::Ordering::Relaxed);
        self.fee_estimator
            .write()
            .record_block(fee_rates, total_mass, self.config.max_block_mass);
    }

    /// Get fee rate estimations.
    pub fn estimate_fee_rates(&self) -> FeerateEstimations {
        self.fee_estimator.read().estimate()
    }

    /// Get detailed fee rate estimations.
    pub fn estimate_fee_rates_verbose(&self) -> FeeEstimateVerbose {
        self.fee_estimator.read().estimate_verbose()
    }

    /// Check if a transaction is in the mempool.
    pub fn has_transaction(&self, tx_id: &[u8; 32]) -> bool {
        self.mempool.read().contains(tx_id)
    }

    /// Get mempool statistics.
    pub fn mempool_stats(&self) -> MempoolStats {
        self.mempool.read().stats()
    }

    /// Get mining counter snapshot.
    pub fn counters_snapshot(&self) -> MiningCountersSnapshot {
        self.counters.snapshot()
    }

    /// Get the number of transactions in the mempool.
    pub fn transaction_count(&self) -> usize {
        self.mempool.read().transaction_count()
    }
}
