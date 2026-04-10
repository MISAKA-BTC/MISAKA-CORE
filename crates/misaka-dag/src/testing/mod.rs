// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Ported from sui commit 5b1d5849e, path: consensus/core/src/test_dag*.rs
//
//! Declarative test infrastructure for DAG consensus.
//!
//! Sui equivalent: test_dag_builder.rs + test_dag_parser.rs + commit_test_fixture.rs
//!
//! Provides:
//! - `DagBuilder`: fluent API for constructing arbitrary DAG topologies
//! - `parse_dag()`: DSL parser for compact test specification
//! - `CommitFixture`: integrated test harness for commit pipeline
//! - `test_dag`: unified facade re-exporting all test infrastructure

pub mod commit_fixture;
pub mod dag_builder;
pub mod dag_parser;
pub mod test_dag;
