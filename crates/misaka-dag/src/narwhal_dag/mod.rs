// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Narwhal DAG state and block management — Sui-aligned.
//!
//! Sui equivalent: consensus/core/ (~8,000 lines)

pub mod admission;
pub mod ancestor;
#[cfg(feature = "anemo-legacy")]
pub mod anemo_network;
pub mod authority_node;
pub mod authority_service;
pub mod block_manager;
pub mod block_subscriber;
pub mod block_verifier;
pub mod broadcaster;
pub mod clock;
pub mod commit_consumer;
pub mod commit_finalizer;
pub mod commit_observer;
pub mod commit_subscriber;
pub mod commit_syncer;
pub mod commit_vote_monitor;
pub mod consensus_wal;
pub mod context;
pub mod core_engine;
pub mod core_thread;
pub mod dag_state;
pub mod epoch;
pub mod leader_schedule;
pub mod leader_scoring;
pub mod leader_timeout;
pub mod metrics;
pub mod network;
pub mod observer_service;
pub mod peer_scorer;
pub mod prometheus;
pub mod proposed_block_handler;
#[cfg(feature = "rocksdb")]
pub mod rocksdb_store;
pub mod round_prober;
pub mod round_tracker;
pub mod runtime;
pub mod slo_metrics;
pub mod slot_equivocation_ledger;
pub mod stake_aggregator;
pub mod store;
pub mod sync_fetcher;
pub mod synchronizer;
pub mod threshold_clock;
pub mod tracing_spans;
pub mod transaction_certifier;
pub mod verify_pool;
pub mod vote_registry;
