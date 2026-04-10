// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Ported from sui commit 5b1d5849e, path: consensus/core/src/test_dag.rs
//
//! Unified facade for declarative DAG testing infrastructure.
//!
//! Re-exports from `dag_builder`, `dag_parser`, and `commit_fixture`
//! into a single import target, matching the Sui `test_dag` module pattern.
//!
//! ## Usage
//!
//! ```ignore
//! use misaka_dag::testing::test_dag::*;
//!
//! // Builder API (programmatic)
//! let mut b = DagBuilder::new_signed(4);
//! b.layer(1).fully_connected().build();
//! b.layer(2).authorities(&[0,1,2]).skip_ancestor(3).build();
//! let dag = b.into_dag_state();
//!
//! // Parser API (DSL)
//! let b = parse_dag(r#"
//!     DAG {
//!         Round 0 : { 4 },
//!         Round 1 : { * },
//!         Round 2 : { A B C },
//!     }
//! "#).unwrap();
//!
//! // Commit fixture (high-level harness)
//! let mut f = CommitFixture::new(4);
//! f.build_layers(1, 3);
//! f.assert_direct_commit(1);
//! ```
//!
//! ## Signing modes
//!
//! | Constructor | Signatures | Use case |
//! |---|---|---|
//! | `DagBuilder::new(committee)` | Dummy (0xAA) | Pure topology tests |
//! | `DagBuilder::new_signed(n)` | Real ML-DSA-65 | Verification tests, audit compliance |
//! | `DagBuilder::from_context(ctx)` | Real ML-DSA-65 | Context integration tests |
//! | `parse_dag(input)` | Dummy | DSL topology tests |
//! | `parse_dag_signed(input)` | Real ML-DSA-65 | DSL + verification tests |
//!
//! ## ML-DSA-65 performance
//!
//! Key generation: ~1.5ms per keypair (cached globally per committee size)
//! Signing: ~0.5ms per block
//! Verification: ~0.3ms per block
//! Signature cache: amortizes signing cost for repeated same-DAG builds

// Re-export builder
pub use super::dag_builder::{
    authority_letter, letter_to_authority, DagBuilder, LayerBuilder, SignatureCache,
};

// Re-export parser
pub use super::dag_parser::{parse_dag, parse_dag_signed, ParseError};

// Re-export commit fixture
pub use super::commit_fixture::CommitFixture;

// Re-export block types needed for DAG construction
pub use crate::narwhal_types::block::{
    AuthorityIndex, Block, BlockDigest, BlockRef, Round, Slot, TestValidatorSet, VerifiedBlock,
};
pub use crate::narwhal_types::committee::Committee;

// Re-export context
pub use crate::narwhal_dag::context::Context;

// Re-export DagState
pub use crate::narwhal_dag::dag_state::{DagState, DagStateConfig};

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the DSL can express the three Sui test_dag canonical examples.
    ///
    /// Example 1: Simple fully-connected 4-node DAG (Sui base_committer tests)
    #[test]
    fn sui_compat_simple_fully_connected() {
        let b = parse_dag(
            r#"
            DAG {
                Round 0 : { 4 },
                Round 1 : { * },
                Round 2 : { * },
                Round 3 : { * },
            }
        "#,
        )
        .unwrap();
        assert_eq!(b.committee().size(), 4);
        assert_eq!(b.blocks_at_round(1).len(), 4);
        assert_eq!(b.blocks_at_round(2).len(), 4);
        assert_eq!(b.blocks_at_round(3).len(), 4);
        // All R2 blocks should reference all R1 blocks
        for blk in b.blocks_at_round(2) {
            assert_eq!(blk.ancestors().len(), 4);
        }
    }

    /// Example 2: Partial connectivity (Sui leader_scoring tests)
    #[test]
    fn sui_compat_partial_connectivity() {
        let b = parse_dag(
            r#"
            DAG {
                Round 0 : { 4 },
                Round 1 : { * },
                Round 2 : {
                    A -> [A1, B1, C1],
                    B -> [*],
                    C -> [A1, B1],
                    D -> [*],
                },
            }
        "#,
        )
        .unwrap();
        // A references 3, B references 4, C references 2, D references 4
        let a = b
            .blocks_at_round(2)
            .into_iter()
            .find(|b| b.author() == 0)
            .unwrap();
        let c = b
            .blocks_at_round(2)
            .into_iter()
            .find(|b| b.author() == 2)
            .unwrap();
        assert_eq!(a.ancestors().len(), 3);
        assert_eq!(c.ancestors().len(), 2);
    }

    /// Example 3: Authority subset (Sui universal_committer tests)
    #[test]
    fn sui_compat_authority_subset() {
        let b = parse_dag(
            r#"
            DAG {
                Round 0 : { 4 },
                Round 1 : { * },
                Round 2 : { A B },
                Round 3 : { * },
            }
        "#,
        )
        .unwrap();
        assert_eq!(b.blocks_at_round(2).len(), 2);
        assert_eq!(b.blocks_at_round(3).len(), 4);
    }

    /// Fixed-seed determinism: same DAG built twice produces identical block hashes.
    #[test]
    fn deterministic_rebuild_identical_hashes() {
        let build = || {
            let b = parse_dag(
                r#"
                DAG {
                    Round 0 : { 4 },
                    Round 1 : { * },
                    Round 2 : { A B C },
                    Round 3 : { * },
                }
            "#,
            )
            .unwrap();
            b.all_blocks()
                .iter()
                .map(|b| b.reference())
                .collect::<Vec<_>>()
        };
        let refs1 = build();
        let refs2 = build();
        assert_eq!(
            refs1, refs2,
            "DAG rebuilds must produce identical block refs"
        );
    }

    /// Equivocation DAG: same author/round, 2 blocks.
    #[test]
    fn equivocation_dag_via_dsl() {
        let b = parse_dag(
            r#"
            DAG {
                Round 0 : { 4 },
                Round 1 : { * },
                Round 2 : { A! B C D },
            }
        "#,
        )
        .unwrap();
        let a_blocks: Vec<_> = b
            .blocks_at_round(2)
            .into_iter()
            .filter(|b| b.author() == 0)
            .collect();
        assert_eq!(a_blocks.len(), 2, "A should have 2 blocks (equivocation)");
        assert_ne!(a_blocks[0].digest(), a_blocks[1].digest());
    }
}
