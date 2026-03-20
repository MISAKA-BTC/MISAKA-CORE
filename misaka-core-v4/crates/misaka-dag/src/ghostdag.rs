//! GhostDAG — Kaspa-Compliant O(1) Reachability-Indexed Engine.
//!
//! # Architecture
//!
//! - `DagStore` trait — block header + GhostDag metadata storage
//! - `InMemoryDagStore` — in-memory implementation for testing
//! - `GhostDagV2` (aliased as `GhostDagEngine`) — production engine
//! - `parent_selection` — canonical sort key and parent selection
//!
//! # Legacy Removal (Phase 3.1)
//!
//! `GhostDagManager` (BFS-based, O(N)) has been **completely removed**.
//! All code paths now use `GhostDagV2` which provides:
//!
//! | Operation | Complexity |
//! |-----------|-----------|
//! | `is_ancestor(A, B)` | O(1) interval check |
//! | `compute_mergeset()` | O(|mergeset| × |parents_per_block|) via BFS + reachability |
//! | `classify_mergeset()` | O(|mergeset| × |blue_set|) via O(1) anticone checks |
//! | `select_parent()` | O(|parents|) via canonical sort key |
//! | `get_total_ordering()` | O(|DAG|) — used only for full replay |

// ── DagStore trait + InMemoryDagStore ──
// These stable interfaces are re-exported from legacy_ghostdag.
// The trait and store impl do NOT depend on GhostDagManager —
// only the data structures and storage abstraction are reused.
pub use crate::legacy_ghostdag::{DagStore, InMemoryDagStore};

// ── Re-export constants ──
pub use crate::constants::MIN_DECOY_DEPTH;

// ── Production engine (V2: Kaspa-compliant reachability-based) ──
pub use crate::ghostdag_v2::{
    GhostDagV2 as GhostDagEngine,
    StakeWeightProvider, UniformStakeProvider,
    HeaderTopologyError, validate_header_topology,
    GhostDagError,
    MAX_PARENTS, MAX_MERGESET_SIZE, PRUNING_WINDOW, DEFAULT_K,
};

// ── Canonical parent selection ──
pub use crate::parent_selection::{
    ParentSortKey, canonical_compare,
    select_canonical_parents, select_parent as canonical_select_parent,
};
