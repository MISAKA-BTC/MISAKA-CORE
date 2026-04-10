// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Consensus Context — single entry point for all consensus configuration.
//!
//! Sui equivalent: `consensus/core/src/context.rs`
//!
//! ## Purpose
//!
//! Before Context, consensus components received their dependencies as
//! individual `Arc<T>` parameters:
//! ```text
//! CoreEngine::new(authority_index, epoch, committee, signer, verifier, chain_ctx)
//! ConsensusRuntime::new(config, signer, store, metrics, ...)
//! BlockVerifier::new(committee, epoch, sig_verifier, chain_ctx)
//! ```
//!
//! This led to:
//! - 6+ parameters per constructor
//! - Epoch transitions requiring updating every struct individually
//! - Inconsistent state when one component is updated but another isn't
//!
//! Context consolidates these into a single immutable snapshot:
//! ```text
//! let ctx = Context::new(own_index, committee, protocol_config, chain_ctx, signer, metrics);
//! CoreEngine::new(ctx.clone())
//! ```
//!
//! Epoch transitions become atomic: build a new Context, swap it in.

use std::sync::Arc;

use crate::narwhal_types::block::{AuthorityIndex, BlockSigner, SignatureVerifier};
use crate::narwhal_types::committee::Committee;
use super::clock::{Clock, SystemClock};
use super::metrics::ConsensusMetrics;

/// Consensus execution context — immutable for the duration of an epoch.
///
/// Contains everything a consensus component needs to operate.
/// When the epoch changes, a new Context is constructed and propagated
/// to all components atomically.
#[derive(Clone)]
pub struct Context {
    /// Our authority index within the committee.
    pub own_index: AuthorityIndex,
    /// Current committee (validator set + stakes).
    pub committee: Arc<Committee>,
    /// Protocol configuration (versioned constants).
    pub protocol_config: Arc<misaka_protocol_config::ProtocolConfig>,
    /// Chain context (chain_id, genesis_hash) for cross-network replay prevention.
    pub chain_ctx: misaka_types::chain_context::ChainContext,
    /// Block signer (ML-DSA-65 in production).
    pub signer: Arc<dyn BlockSigner>,
    /// Signature verifier (ML-DSA-65 in production).
    pub sig_verifier: Arc<dyn SignatureVerifier>,
    /// Prometheus metrics (shared across all components).
    pub metrics: Arc<ConsensusMetrics>,
    /// Clock abstraction (SystemClock in production, SimulatedClock in tests).
    ///
    /// Phase 0-2 completion: Sui's Context carries `Arc<dyn Clock>`.
    /// All consensus code that needs wall-clock time goes through this.
    pub clock: Arc<dyn Clock>,
}

impl Context {
    /// Create a new consensus context.
    pub fn new(
        own_index: AuthorityIndex,
        committee: Committee,
        protocol_config: misaka_protocol_config::ProtocolConfig,
        chain_ctx: misaka_types::chain_context::ChainContext,
        signer: Arc<dyn BlockSigner>,
        sig_verifier: Arc<dyn SignatureVerifier>,
        metrics: Arc<ConsensusMetrics>,
    ) -> Self {
        Self {
            own_index,
            committee: Arc::new(committee),
            protocol_config: Arc::new(protocol_config),
            chain_ctx,
            signer,
            sig_verifier,
            metrics,
            clock: Arc::new(SystemClock),
        }
    }

    /// Create a context with a custom clock (for deterministic simulation).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Current epoch (from the committee).
    pub fn epoch(&self) -> u64 {
        self.committee.epoch
    }

    /// Committee size (number of authorities).
    pub fn committee_size(&self) -> usize {
        self.committee.size()
    }

    /// Create a test context with default/minimal parameters.
    ///
    /// Uses `MlDsa65TestSigner` and `MlDsa65Verifier` for real crypto
    /// in test builds.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_test(num_authorities: usize) -> Self {
        use crate::narwhal_types::block::{MlDsa65TestSigner, MlDsa65Verifier, TestValidatorSet};
        use super::clock::SimulatedClock;

        let vs = TestValidatorSet::new(num_authorities);
        let committee = vs.committee();
        let signer = vs.signer(0);
        let sig_verifier: Arc<dyn SignatureVerifier> = Arc::new(MlDsa65Verifier);
        let chain_ctx = TestValidatorSet::chain_ctx();
        let protocol_config = misaka_protocol_config::ProtocolConfig::latest();
        let metrics = Arc::new(ConsensusMetrics::new());

        Self {
            own_index: 0,
            committee: Arc::new(committee),
            protocol_config: Arc::new(protocol_config),
            chain_ctx,
            signer,
            sig_verifier,
            metrics,
            clock: Arc::new(SimulatedClock::new(super::clock::SIM_CLOCK_DEFAULT_START_MS)),
        }
    }

    /// Create a test context for a specific authority index.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_test_with_index(num_authorities: usize, own_index: AuthorityIndex) -> Self {
        let mut ctx = Self::new_for_test(num_authorities);
        ctx.own_index = own_index;
        // Use the correct signer for this authority
        let vs = crate::narwhal_types::block::TestValidatorSet::new(num_authorities);
        ctx.signer = vs.signer(own_index as usize);
        ctx
    }
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("own_index", &self.own_index)
            .field("epoch", &self.epoch())
            .field("committee_size", &self.committee_size())
            .field("protocol_version", &self.protocol_config.version)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_creation() {
        let ctx = Context::new_for_test(4);
        assert_eq!(ctx.own_index, 0);
        assert_eq!(ctx.committee_size(), 4);
        assert_eq!(ctx.epoch(), 0);
        assert_eq!(ctx.protocol_config.num_validators(), 21);
    }

    #[test]
    fn test_context_with_index() {
        let ctx = Context::new_for_test_with_index(4, 2);
        assert_eq!(ctx.own_index, 2);
        assert_eq!(ctx.committee_size(), 4);
    }

    #[test]
    fn test_context_clone_shares_arcs() {
        let ctx1 = Context::new_for_test(4);
        let ctx2 = ctx1.clone();
        // Arc pointers should be the same
        assert!(Arc::ptr_eq(&ctx1.committee, &ctx2.committee));
        assert!(Arc::ptr_eq(&ctx1.protocol_config, &ctx2.protocol_config));
        assert!(Arc::ptr_eq(&ctx1.metrics, &ctx2.metrics));
    }

    #[test]
    fn test_epoch_transition_is_new_context() {
        let ctx_epoch0 = Context::new_for_test(4);
        assert_eq!(ctx_epoch0.epoch(), 0);
        // Epoch transition: create entirely new context
        // (in production, this would use the new committee from epoch change)
        let ctx_epoch1 = Context::new_for_test(4);
        // They are independent snapshots
        assert!(!Arc::ptr_eq(&ctx_epoch0.committee, &ctx_epoch1.committee));
    }
}
