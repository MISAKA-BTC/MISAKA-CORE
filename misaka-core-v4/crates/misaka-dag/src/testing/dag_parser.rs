// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Ported from sui commit 5b1d5849e, path: consensus/core/src/test_dag_parser.rs
//
//! DSL parser for declarative DAG test specifications.
//!
//! # Grammar
//!
//! ```text
//! DAG {
//!     Round 0 : { <num_authorities> },        // genesis (committee size)
//!     Round 1 : { * },                        // all authorities, fully connected
//!     Round 2 : { A B C },                    // subset of authorities
//!     Round 3 : {
//!         A -> [*],                           // A links to all prev-round blocks
//!         B -> [A2, C2],                      // B links to specific blocks
//!         C -> [-D2],                         // C links to all EXCEPT D's R2 block
//!     },
//!     Round 4 : { A! B },                     // A equivocates (produces 2 blocks)
//!     Round 5 : { A!! },                      // A produces 3 blocks (1 primary + 2 equivocating)
//! }
//! ```
//!
//! ## Equivocation syntax (Phase 1-3 extension)
//!
//! Append `!` after an authority letter to produce equivocating blocks.
//! Each `!` adds one extra block at the same (author, round) slot with
//! a different digest. `A!` = 1 equivocating block, `A!!` = 2, etc.

use super::dag_builder::*;
use crate::narwhal_types::block::*;
use crate::narwhal_types::committee::Committee;

use std::collections::HashMap;

/// Parse a DAG specification into a `DagBuilder`.
///
/// The returned builder owns a fully constructed DAG; call
/// `.into_dag_state()` or `.to_dag_state()` to feed it into
/// a `DagState` for commit testing.
pub fn parse_dag(input: &str) -> Result<DagBuilder, ParseError> {
    Parser::new(input).parse()
}

/// Parse a DAG specification using real ML-DSA-65 signatures.
///
/// Like `parse_dag`, but creates a `DagBuilder::new_signed(n)` instead
/// of `DagBuilder::new(committee)`. Blocks will have real signatures.
pub fn parse_dag_signed(input: &str) -> Result<DagBuilder, ParseError> {
    Parser::new(input).parse_signed()
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("line {line}, col {col}: {msg}")]
    Syntax { line: usize, col: usize, msg: String },
}

// ── Internal parser ────────────────────────────────────────

struct Parser<'a> {
    src: &'a str,
    pos: usize,
    line: usize,
    col: usize,
    builder: Option<DagBuilder>,
    signed: bool,
}

impl<'a> Parser<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src,
            pos: 0,
            line: 1,
            col: 1,
            builder: None,
            signed: false,
        }
    }

    fn parse(&mut self) -> Result<DagBuilder, ParseError> {
        self.signed = false;
        self.parse_inner()
    }

    fn parse_signed(&mut self) -> Result<DagBuilder, ParseError> {
        self.signed = true;
        self.parse_inner()
    }

    fn parse_inner(&mut self) -> Result<DagBuilder, ParseError> {
        self.ws();
        self.expect_kw("DAG")?;
        self.ws();
        self.expect_ch('{')?;

        loop {
            self.ws();
            if self.peek() == Some('}') {
                self.adv();
                break;
            }
            if self.eof() {
                return Err(self.err("unexpected EOF, expected '}'"));
            }
            self.parse_round()?;
            self.ws();
            if self.peek() == Some(',') {
                self.adv();
            }
        }

        self.builder
            .take()
            .ok_or_else(|| self.err("no genesis round"))
    }

    fn parse_round(&mut self) -> Result<(), ParseError> {
        self.ws();
        self.expect_kw("Round")?;
        self.ws();
        let round = self.parse_u32()? as Round;
        self.ws();
        self.expect_ch(':')?;
        self.ws();
        self.expect_ch('{')?;
        self.ws();

        if round == 0 {
            let n = self.parse_u32()? as usize;
            if n == 0 {
                return Err(self.err("committee size must be >= 1"));
            }
            self.ws();
            self.expect_ch('}')?;
            self.builder = Some(if self.signed {
                DagBuilder::new_signed(n)
            } else {
                DagBuilder::new(Committee::new_for_test(n))
            });
            return Ok(());
        }

        if self.builder.is_none() {
            return Err(self.err("Round 0 must come first"));
        }

        // Parse the round body FIRST (no mutable borrow of builder),
        // then apply to builder afterwards (avoids borrow checker conflict).
        enum RoundBody {
            FullyConnected,
            AuthSubset(Vec<(AuthorityIndex, usize)>), // (auth, equivocate_count)
            Connections(Vec<(AuthorityIndex, Vec<BlockRef>)>),
            Empty,
        }

        let body = if self.peek() == Some('*') {
            self.adv();
            self.ws();
            self.expect_ch('}')?;
            RoundBody::FullyConnected
        } else if self.is_conn_spec() {
            // Clone the builder for read-only reference to avoid borrow conflict
            let dag_snapshot = self.builder.as_ref().unwrap().clone();
            let conns = self.parse_connections(&dag_snapshot, round)?;
            self.ws();
            self.expect_ch('}')?;
            RoundBody::Connections(conns)
        } else if self.peek_is_alpha() {
            let auths = self.parse_auth_list_with_equivocation()?;
            self.ws();
            self.expect_ch('}')?;
            RoundBody::AuthSubset(auths)
        } else {
            self.ws();
            self.expect_ch('}')?;
            RoundBody::Empty
        };

        // Now mutably borrow builder and apply
        let dag = self.builder.as_mut().unwrap();
        match body {
            RoundBody::FullyConnected => {
                dag.layer(round).fully_connected().build();
            }
            RoundBody::AuthSubset(auths) => {
                // Validate all authorities are within committee bounds
                let n = dag.committee().size() as AuthorityIndex;
                for &(auth, _) in &auths {
                    if auth >= n {
                        return Err(self.err(&format!(
                            "authority {} exceeds committee size {}",
                            authority_letter(auth),
                            n
                        )));
                    }
                }

                // Check if any authority has equivocation
                let max_eq = auths.iter().map(|(_, eq)| *eq).max().unwrap_or(0);
                let auth_indices: Vec<AuthorityIndex> =
                    auths.iter().map(|(a, _)| *a).collect();

                if max_eq > 0 {
                    // Build without equivocation first for non-equivocating authorities
                    let non_eq: Vec<AuthorityIndex> = auths
                        .iter()
                        .filter(|(_, eq)| *eq == 0)
                        .map(|(a, _)| *a)
                        .collect();
                    if !non_eq.is_empty() {
                        dag.layer(round)
                            .authorities(&non_eq)
                            .fully_connected()
                            .build();
                    }
                    // Build equivocating authorities separately
                    for (auth, eq_count) in &auths {
                        if *eq_count > 0 {
                            dag.layer(round)
                                .authorities(&[*auth])
                                .fully_connected()
                                .equivocate(*eq_count)
                                .build();
                        }
                    }
                } else {
                    dag.layer(round)
                        .authorities(&auth_indices)
                        .fully_connected()
                        .build();
                }
            }
            RoundBody::Connections(conns) => {
                let mut map = HashMap::new();
                for (auth, refs) in conns {
                    map.insert(auth, refs);
                }
                dag.layer(round).custom_ancestors(map).build();
            }
            RoundBody::Empty => {}
        }
        Ok(())
    }

    // ── Connection spec parsing ──

    fn parse_connections(
        &mut self,
        dag: &DagBuilder,
        _round: Round,
    ) -> Result<Vec<(AuthorityIndex, Vec<BlockRef>)>, ParseError> {
        let mut out = Vec::new();
        loop {
            self.ws();
            if self.peek() == Some('}') {
                break;
            }
            let auth = self.parse_authority()?;
            self.ws();
            self.expect_kw("->")?;
            self.ws();
            self.expect_ch('[')?;
            let refs = self.parse_ref_list(dag)?;
            self.ws();
            self.expect_ch(']')?;
            self.ws();
            if self.peek() == Some(',') {
                self.adv();
            }
            out.push((auth, refs));
        }
        Ok(out)
    }

    fn parse_ref_list(&mut self, dag: &DagBuilder) -> Result<Vec<BlockRef>, ParseError> {
        let mut includes = Vec::new();
        let mut excludes = Vec::new();
        let mut use_all = false;

        loop {
            self.ws();
            if self.peek() == Some(']') {
                break;
            }
            if self.peek() == Some('*') {
                self.adv();
                use_all = true;
            } else if self.peek() == Some('-') {
                self.adv();
                excludes.push(self.parse_block_ref(dag)?);
            } else {
                includes.push(self.parse_block_ref(dag)?);
            }
            self.ws();
            if self.peek() == Some(',') {
                self.adv();
            }
        }

        if use_all || !excludes.is_empty() {
            // Exclusion implies "all except these" even without explicit '*'
            let all: Vec<BlockRef> = dag
                .last_refs
                .iter()
                .filter_map(|o| *o)
                .filter(|r| !excludes.contains(r))
                .collect();
            let mut result = all;
            for inc in includes {
                if !result.contains(&inc) {
                    result.push(inc);
                }
            }
            Ok(result)
        } else {
            Ok(includes)
        }
    }

    fn parse_block_ref(&mut self, dag: &DagBuilder) -> Result<BlockRef, ParseError> {
        let auth = self.parse_authority()?;
        let round = self.parse_u32()? as Round;
        dag.blocks
            .values()
            .find(|b| b.author() == auth && b.round() == round)
            .map(|b| b.reference())
            .ok_or_else(|| {
                self.err(&format!(
                    "block {}{} not found in DAG",
                    authority_letter(auth),
                    round
                ))
            })
    }

    fn parse_authority(&mut self) -> Result<AuthorityIndex, ParseError> {
        match self.peek() {
            Some(c) if c.is_ascii_uppercase() => {
                self.adv();
                letter_to_authority(c).ok_or_else(|| self.err("bad authority"))
            }
            Some('[') => {
                self.adv();
                let n = self.parse_u32()?;
                self.expect_ch(']')?;
                Ok(n)
            }
            _ => Err(self.err("expected authority letter (A-Z) or [N]")),
        }
    }

    /// Parse authority list with optional equivocation markers.
    /// `A B C` → [(0,0), (1,0), (2,0)]
    /// `A! B C` → [(0,1), (1,0), (2,0)]
    /// `A!! B` → [(0,2), (1,0)]
    fn parse_auth_list_with_equivocation(
        &mut self,
    ) -> Result<Vec<(AuthorityIndex, usize)>, ParseError> {
        let mut list = Vec::new();
        loop {
            self.ws();
            match self.peek() {
                Some(c) if c.is_ascii_uppercase() => {
                    self.adv();
                    let auth =
                        letter_to_authority(c).ok_or_else(|| self.err("bad authority"))?;
                    // Count trailing '!' for equivocation
                    let mut eq_count = 0;
                    while self.peek() == Some('!') {
                        self.adv();
                        eq_count += 1;
                    }
                    list.push((auth, eq_count));
                }
                _ => break,
            }
        }
        Ok(list)
    }

    fn parse_u32(&mut self) -> Result<u32, ParseError> {
        let start = self.pos;
        while self.peek().map_or(false, |c| c.is_ascii_digit()) {
            self.adv();
        }
        if self.pos == start {
            return Err(self.err("expected number"));
        }
        self.src[start..self.pos]
            .parse::<u32>()
            .map_err(|e| self.err(&format!("bad number: {e}")))
    }

    // ── Lookahead ──

    fn is_conn_spec(&self) -> bool {
        let rest = self.src[self.pos..].trim_start();
        if rest.len() < 4 {
            return false;
        }
        let first = rest.chars().next().unwrap_or(' ');
        if !first.is_ascii_uppercase() {
            return false;
        }
        // Skip equivocation markers ('!') before checking for '->'
        let after_auth = &rest[1..];
        let trimmed = after_auth.trim_start_matches('!').trim_start();
        trimmed.starts_with("->")
    }

    fn peek_is_alpha(&self) -> bool {
        self.peek().map_or(false, |c| c.is_ascii_uppercase())
    }

    // ── Lexer primitives ──

    fn peek(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    fn adv(&mut self) {
        if let Some(c) = self.peek() {
            self.pos += c.len_utf8();
            if c == '\n' {
                self.line += 1;
                self.col = 1;
            } else {
                self.col += 1;
            }
        }
    }

    fn eof(&self) -> bool {
        self.pos >= self.src.len()
    }

    fn ws(&mut self) {
        loop {
            match self.peek() {
                Some(c) if c.is_whitespace() => self.adv(),
                Some('/') if self.src[self.pos..].starts_with("//") => {
                    while self.peek().map_or(false, |c| c != '\n') {
                        self.adv();
                    }
                }
                _ => break,
            }
        }
    }

    fn expect_ch(&mut self, ch: char) -> Result<(), ParseError> {
        if self.peek() == Some(ch) {
            self.adv();
            Ok(())
        } else {
            let got = self
                .peek()
                .map(|c| format!("'{c}'"))
                .unwrap_or_else(|| "EOF".to_string());
            Err(self.err(&format!("expected '{ch}', got {got}")))
        }
    }

    fn expect_kw(&mut self, kw: &str) -> Result<(), ParseError> {
        if self.src[self.pos..].starts_with(kw) {
            for _ in kw.chars() {
                self.adv();
            }
            Ok(())
        } else {
            let remaining = &self.src[self.pos..];
            let got: String = remaining.chars().take(kw.len()).collect();
            Err(self.err(&format!("expected '{kw}', got '{got}'")))
        }
    }

    fn err(&self, msg: &str) -> ParseError {
        ParseError::Syntax {
            line: self.line,
            col: self.col,
            msg: msg.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple() {
        let b = parse_dag(
            r#"
            DAG {
                Round 0 : { 4 },
                Round 1 : { * },
                Round 2 : { * },
            }
        "#,
        )
        .unwrap();
        assert_eq!(b.committee().size(), 4);
        assert_eq!(b.blocks_at_round(1).len(), 4);
        assert_eq!(b.blocks_at_round(2).len(), 4);
    }

    #[test]
    fn parse_authority_subset() {
        let b = parse_dag(
            r#"
            DAG {
                Round 0 : { 4 },
                Round 1 : { * },
                Round 2 : { A B C },
            }
        "#,
        )
        .unwrap();
        assert_eq!(b.blocks_at_round(2).len(), 3);
    }

    #[test]
    fn parse_connection_spec() {
        let b = parse_dag(
            r#"
            DAG {
                Round 0 : { 4 },
                Round 1 : { * },
                Round 2 : {
                    A -> [A1, B1],
                    B -> [*],
                },
            }
        "#,
        )
        .unwrap();
        let a_block = b
            .blocks_at_round(2)
            .into_iter()
            .find(|b| b.author() == 0)
            .unwrap();
        assert_eq!(a_block.ancestors().len(), 2);
    }

    #[test]
    fn parse_exclusion() {
        let b = parse_dag(
            r#"
            DAG {
                Round 0 : { 4 },
                Round 1 : { * },
                Round 2 : {
                    A -> [-D1],
                },
            }
        "#,
        )
        .unwrap();
        let a_block = b
            .blocks_at_round(2)
            .into_iter()
            .find(|b| b.author() == 0)
            .unwrap();
        assert_eq!(a_block.ancestors().len(), 3); // all except D
    }

    #[test]
    fn parse_comments() {
        let b = parse_dag(
            r#"
            DAG {
                Round 0 : { 4 },   // genesis
                Round 1 : { * },   // all connected
            }
        "#,
        )
        .unwrap();
        assert_eq!(b.blocks_at_round(1).len(), 4);
    }

    #[test]
    fn roundtrip_dump() {
        let mut b = DagBuilder::new(Committee::new_for_test(4));
        b.build_layers(1, 3);
        let dump = b.dump();
        assert!(dump.contains("R1:"));
        assert!(dump.contains("R3:"));
    }

    // ── Phase 1-3: Equivocation DSL ────────────────────────

    #[test]
    fn parse_equivocation_single() {
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
        // A produces 2 blocks (1 primary + 1 equivocating), B/C/D produce 1 each
        assert_eq!(b.blocks_at_round(2).len(), 5);
        let a_blocks: Vec<_> = b
            .blocks_at_round(2)
            .into_iter()
            .filter(|b| b.author() == 0)
            .collect();
        assert_eq!(a_blocks.len(), 2);
        assert_ne!(a_blocks[0].digest(), a_blocks[1].digest());
    }

    #[test]
    fn parse_equivocation_double() {
        let b = parse_dag(
            r#"
            DAG {
                Round 0 : { 4 },
                Round 1 : { * },
                Round 2 : { A!! B },
            }
        "#,
        )
        .unwrap();
        // A: 1 primary + 2 equivocating = 3, B: 1
        assert_eq!(b.blocks_at_round(2).len(), 4);
        let a_blocks: Vec<_> = b
            .blocks_at_round(2)
            .into_iter()
            .filter(|b| b.author() == 0)
            .collect();
        assert_eq!(a_blocks.len(), 3);
    }

    // ── Phase 1-3: Error messages with line + column ───────

    #[test]
    fn error_includes_line_and_col() {
        // Use a structurally invalid input (missing colon after Round number)
        let result = parse_dag(
            r#"
            DAG {
                Round 0 : { 4 },
                Round 1 { * },
            }
        "#,
        );
        let err = result.unwrap_err();
        let msg = err.to_string();
        // Error should include "line" and "col"
        assert!(
            msg.contains("line") && msg.contains("col"),
            "error message should include line and col: {msg}"
        );
    }

    #[test]
    fn error_on_missing_genesis() {
        let result = parse_dag("DAG { Round 1 : { * } }");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Round 0 must come first"), "got: {msg}");
    }

    #[test]
    fn error_on_unexpected_eof() {
        let result = parse_dag("DAG {");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("EOF"), "got: {msg}");
    }

    #[test]
    fn error_on_invalid_block_ref() {
        let result = parse_dag(
            r#"
            DAG {
                Round 0 : { 4 },
                Round 1 : { * },
                Round 2 : {
                    A -> [Z9],
                },
            }
        "#,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not found"), "got: {msg}");
    }

    // ── Signed DAG parsing ─────────────────────────────────

    #[test]
    fn parse_dag_signed_produces_real_sigs() {
        let b = parse_dag_signed(
            r#"
            DAG {
                Round 0 : { 4 },
                Round 1 : { * },
            }
        "#,
        )
        .unwrap();
        assert!(b.is_signed());
        for blk in b.blocks_at_round(1) {
            assert_eq!(blk.inner().signature.len(), 3309);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Proptest: parser must never panic on arbitrary input
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod proptest_fuzz {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10_000))]

        /// Parser must return Ok or Err — never panic — on arbitrary input.
        #[test]
        fn parser_never_panics_on_arbitrary_input(input in "\\PC{0,500}") {
            let _ = parse_dag(&input);
        }

        /// Parser must not panic on inputs that look like partial DAG specs.
        #[test]
        fn parser_never_panics_on_dag_like_input(
            prefix in "(DAG)?",
            brace in "[{} ]*",
            body in "[A-Z0-9:!,\\->\\[\\]\\* \n\t]*",
        ) {
            let input = format!("{prefix} {brace} {body}");
            let _ = parse_dag(&input);
        }

        /// Parser must not panic on round-like patterns.
        #[test]
        fn parser_never_panics_on_round_patterns(
            n in 0u32..100,
            auths in "[A-Z!]{0,10}",
        ) {
            let input = format!("DAG {{ Round 0 : {{ {n} }}, Round 1 : {{ {auths} }} }}");
            let _ = parse_dag(&input);
        }

        /// Parser error messages must always include line and col.
        #[test]
        fn parser_errors_always_have_position(input in "[A-Z0-9 {}:,\n]{1,200}") {
            if let Err(e) = parse_dag(&input) {
                let msg = e.to_string();
                prop_assert!(
                    msg.contains("line") && msg.contains("col"),
                    "error missing position info: {msg}"
                );
            }
        }
    }
}
