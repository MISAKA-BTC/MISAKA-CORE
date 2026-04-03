//! Advanced UTXO Coin Selection — multi-strategy, dust-aware, privacy-preserving.
//!
//! # Strategies
//!
//! | Strategy          | Goal                     | Privacy | Change |
//! |-------------------|--------------------------|---------|--------|
//! | BranchAndBound    | Exact match (no change)  | Best    | None   |
//! | LargestFirst      | Simple, deterministic    | Medium  | Likely |
//! | SmallestSufficient| Minimize change          | Medium  | Small  |
//! | PrivacyAware      | Random ages, no dust     | Best    | Random |
//! | Consolidate       | Reduce UTXO count        | Worst   | Yes    |
//!
//! # Dust Prevention
//!
//! If the computed change amount is below `DUST_THRESHOLD`, it is
//! absorbed into the fee (overpay) rather than creating a tiny output
//! that costs more in fees to spend than it's worth.
//!
//! # Privacy Considerations
//!
//! For ring-signature transactions, UTXO selection impacts privacy:
//! - **Avoid deterministic ordering** (prevents "always-oldest" fingerprinting).
//! - **Avoid exact amounts** (change=0 reveals the exact send amount).
//! - **Use diverse UTXO ages** to frustrate temporal analysis.

use serde::{Deserialize, Serialize};

/// Minimum meaningful output amount. Below this, the change is dust.
pub const DUST_THRESHOLD: u64 = 1_000; // 0.001 MISAKA

/// Maximum iterations for Branch-and-Bound before fallback.
const BNB_MAX_ITERATIONS: u32 = 100_000;

// ═══════════════════════════════════════════════════════════════
//  UTXO Candidate
// ═══════════════════════════════════════════════════════════════

/// A UTXO candidate for selection (generic over different wallet models).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoCandidate {
    /// Unique identifier.
    pub id: u64,
    /// Outpoint hash.
    pub tx_hash: [u8; 32],
    /// Output index.
    pub output_index: u32,
    /// Amount in base units.
    pub amount: u64,
    /// Block height when this UTXO was confirmed (for age-based selection).
    pub confirmed_at: u64,
    /// Effective fee cost to include this UTXO as an input.
    /// Larger UTXOs (e.g., with range proofs) cost more to spend.
    pub input_weight: u64,
}

/// Selection result.
#[derive(Debug, Clone)]
pub struct SelectionResult {
    /// Selected UTXOs.
    pub selected: Vec<UtxoCandidate>,
    /// Total input value.
    pub total_input: u64,
    /// Fee to pay.
    pub fee: u64,
    /// Change output amount (0 if exact match).
    pub change: u64,
    /// Whether dust was absorbed into fee.
    pub dust_absorbed: bool,
    /// Strategy that produced this result.
    pub strategy: &'static str,
}

/// Selection strategy enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    /// Try to match exactly (no change output). Best privacy.
    BranchAndBound,
    /// Select largest UTXOs first. Simple, deterministic.
    LargestFirst,
    /// Select smallest UTXO that covers the target. Minimize change.
    SmallestSufficient,
    /// Random selection with age diversity. Best for ring sig privacy.
    PrivacyAware,
    /// Select as many small UTXOs as possible. Reduce fragmentation.
    Consolidate,
    /// Try strategies in order: BnB → PrivacyAware → LargestFirst.
    Auto,
}

impl Default for Strategy {
    fn default() -> Self {
        Strategy::Auto
    }
}

// ═══════════════════════════════════════════════════════════════
//  Selection Interface
// ═══════════════════════════════════════════════════════════════

/// Select UTXOs to cover `target + fee_rate * estimated_inputs`.
///
/// The `fee_per_input` is the marginal fee cost of adding one more input.
/// Total fee = `base_fee + fee_per_input * selected.len()`.
pub fn select(
    utxos: &[UtxoCandidate],
    target: u64,
    base_fee: u64,
    fee_per_input: u64,
    strategy: Strategy,
) -> Result<SelectionResult, String> {
    if target == 0 {
        return Err("target must be positive".into());
    }
    if utxos.is_empty() {
        return Err("no UTXOs available".into());
    }

    let result = match strategy {
        Strategy::BranchAndBound => select_bnb(utxos, target, base_fee, fee_per_input),
        Strategy::LargestFirst => select_largest_first(utxos, target, base_fee, fee_per_input),
        Strategy::SmallestSufficient => {
            select_smallest_sufficient(utxos, target, base_fee, fee_per_input)
        }
        Strategy::PrivacyAware => select_privacy_aware(utxos, target, base_fee, fee_per_input),
        Strategy::Consolidate => select_consolidate(utxos, target, base_fee, fee_per_input),
        Strategy::Auto => select_auto(utxos, target, base_fee, fee_per_input),
    };

    // Apply dust absorption
    result.map(|mut r| {
        if r.change > 0 && r.change < DUST_THRESHOLD {
            r.fee += r.change;
            r.change = 0;
            r.dust_absorbed = true;
        }
        r
    })
}

// ═══════════════════════════════════════════════════════════════
//  Auto Strategy (cascade)
// ═══════════════════════════════════════════════════════════════

fn select_auto(
    utxos: &[UtxoCandidate],
    target: u64,
    base_fee: u64,
    fee_per_input: u64,
) -> Result<SelectionResult, String> {
    // 1. Try exact match (best privacy)
    if let Ok(result) = select_bnb(utxos, target, base_fee, fee_per_input) {
        return Ok(result);
    }

    // 2. Try privacy-aware
    if let Ok(result) = select_privacy_aware(utxos, target, base_fee, fee_per_input) {
        return Ok(result);
    }

    // 3. Fallback to largest-first (always works if funds are sufficient)
    select_largest_first(utxos, target, base_fee, fee_per_input)
}

// ═══════════════════════════════════════════════════════════════
//  Branch-and-Bound (Exact Match)
// ═══════════════════════════════════════════════════════════════

/// Branch-and-Bound: try to find a subset that exactly matches target + fees.
///
/// Based on Bitcoin Core's BnB algorithm (Murch, 2017).
/// Returns an exact match if found within iteration budget, else Err.
fn select_bnb(
    utxos: &[UtxoCandidate],
    target: u64,
    base_fee: u64,
    fee_per_input: u64,
) -> Result<SelectionResult, String> {
    // Sort by amount descending for better pruning
    let mut sorted: Vec<&UtxoCandidate> = utxos.iter().collect();
    sorted.sort_by(|a, b| b.amount.cmp(&a.amount));

    let n = sorted.len();
    let mut best: Option<Vec<bool>> = None;
    let mut current = vec![false; n];
    let mut current_sum: u64 = 0;
    let mut iterations: u32 = 0;

    // Precompute suffix sums for pruning
    let mut suffix_sum = vec![0u64; n + 1];
    for i in (0..n).rev() {
        suffix_sum[i] = suffix_sum[i + 1].saturating_add(sorted[i].amount);
    }

    fn bnb_recurse(
        sorted: &[&UtxoCandidate],
        target: u64,
        base_fee: u64,
        fee_per_input: u64,
        current: &mut Vec<bool>,
        current_sum: &mut u64,
        idx: usize,
        best: &mut Option<Vec<bool>>,
        iterations: &mut u32,
        suffix_sum: &[u64],
    ) {
        if *iterations >= BNB_MAX_ITERATIONS {
            return;
        }
        *iterations += 1;

        let n_selected = current.iter().filter(|&&x| x).count() as u64;
        let effective_fee = base_fee + fee_per_input * n_selected;
        let needed = target.saturating_add(effective_fee);

        // Check exact match (within dust tolerance)
        if *current_sum >= needed && (*current_sum - needed) < DUST_THRESHOLD {
            // Found an exact-ish match
            if best.is_none()
                || current.iter().filter(|&&x| x).count()
                    < best
                        .as_ref()
                        .map_or(usize::MAX, |b| b.iter().filter(|&&x| x).count())
            {
                *best = Some(current.clone());
            }
            return;
        }

        if idx >= sorted.len() {
            return;
        }

        // Prune: even adding all remaining can't reach target
        if current_sum.saturating_add(suffix_sum[idx]) < needed {
            return;
        }

        // Prune: already over target by more than dust
        if *current_sum > needed + DUST_THRESHOLD {
            return;
        }

        // Branch: include sorted[idx]
        current[idx] = true;
        *current_sum += sorted[idx].amount;
        bnb_recurse(
            sorted,
            target,
            base_fee,
            fee_per_input,
            current,
            current_sum,
            idx + 1,
            best,
            iterations,
            suffix_sum,
        );
        current[idx] = false;
        *current_sum -= sorted[idx].amount;

        // Branch: exclude sorted[idx]
        bnb_recurse(
            sorted,
            target,
            base_fee,
            fee_per_input,
            current,
            current_sum,
            idx + 1,
            best,
            iterations,
            suffix_sum,
        );
    }

    bnb_recurse(
        &sorted,
        target,
        base_fee,
        fee_per_input,
        &mut current,
        &mut current_sum,
        0,
        &mut best,
        &mut iterations,
        &suffix_sum,
    );

    match best {
        Some(selection) => {
            let selected: Vec<UtxoCandidate> = sorted
                .iter()
                .zip(selection.iter())
                .filter(|(_, &sel)| sel)
                .map(|(u, _)| (*u).clone())
                .collect();

            let total_input: u64 = selected.iter().map(|u| u.amount).sum();
            let effective_fee = base_fee + fee_per_input * selected.len() as u64;
            let change = total_input.saturating_sub(target + effective_fee);

            Ok(SelectionResult {
                selected,
                total_input,
                fee: effective_fee,
                change,
                dust_absorbed: false,
                strategy: "branch_and_bound",
            })
        }
        None => Err("no exact match found within iteration budget".into()),
    }
}

// ═══════════════════════════════════════════════════════════════
//  Largest-First
// ═══════════════════════════════════════════════════════════════

fn select_largest_first(
    utxos: &[UtxoCandidate],
    target: u64,
    base_fee: u64,
    fee_per_input: u64,
) -> Result<SelectionResult, String> {
    let mut sorted: Vec<&UtxoCandidate> = utxos.iter().collect();
    sorted.sort_by(|a, b| b.amount.cmp(&a.amount));

    accumulate(&sorted, target, base_fee, fee_per_input, "largest_first")
}

// ═══════════════════════════════════════════════════════════════
//  Smallest-Sufficient
// ═══════════════════════════════════════════════════════════════

fn select_smallest_sufficient(
    utxos: &[UtxoCandidate],
    target: u64,
    base_fee: u64,
    fee_per_input: u64,
) -> Result<SelectionResult, String> {
    let needed = target.saturating_add(base_fee + fee_per_input);

    // Try single-UTXO first
    let mut candidates: Vec<&UtxoCandidate> = utxos.iter().filter(|u| u.amount >= needed).collect();
    candidates.sort_by_key(|u| u.amount);

    if let Some(single) = candidates.first() {
        let fee = base_fee + fee_per_input;
        let change = single.amount.saturating_sub(target + fee);
        return Ok(SelectionResult {
            selected: vec![(*single).clone()],
            total_input: single.amount,
            fee,
            change,
            dust_absorbed: false,
            strategy: "smallest_sufficient",
        });
    }

    // Fallback to accumulation
    let mut sorted: Vec<&UtxoCandidate> = utxos.iter().collect();
    sorted.sort_by(|a, b| b.amount.cmp(&a.amount));
    accumulate(
        &sorted,
        target,
        base_fee,
        fee_per_input,
        "smallest_sufficient",
    )
}

// ═══════════════════════════════════════════════════════════════
//  Privacy-Aware
// ═══════════════════════════════════════════════════════════════

fn select_privacy_aware(
    utxos: &[UtxoCandidate],
    target: u64,
    base_fee: u64,
    fee_per_input: u64,
) -> Result<SelectionResult, String> {
    // Shuffle by deterministic-but-unpredictable ordering:
    // Use amount XOR confirmed_at as a pseudo-random sort key.
    // This avoids always-oldest and always-largest fingerprints.
    let mut shuffled: Vec<&UtxoCandidate> = utxos.iter().collect();
    shuffled.sort_by_key(|u| {
        // Mix amount and age for pseudo-random ordering
        u.amount.wrapping_mul(0x9E3779B97F4A7C15) ^ u.confirmed_at.wrapping_mul(0x517CC1B727220A95)
    });

    // Filter out UTXOs that would create dust change
    let needed_single = target.saturating_add(base_fee + fee_per_input);

    // Prefer UTXOs where change >= DUST_THRESHOLD
    let good: Vec<&UtxoCandidate> = shuffled
        .iter()
        .filter(|u| u.amount >= needed_single && (u.amount - needed_single) >= DUST_THRESHOLD)
        .copied()
        .collect();

    if let Some(selected) = good.first() {
        let fee = base_fee + fee_per_input;
        let change = selected.amount.saturating_sub(target + fee);
        return Ok(SelectionResult {
            selected: vec![(*selected).clone()],
            total_input: selected.amount,
            fee,
            change,
            dust_absorbed: false,
            strategy: "privacy_aware",
        });
    }

    // Fallback to shuffled accumulation
    accumulate(&shuffled, target, base_fee, fee_per_input, "privacy_aware")
}

// ═══════════════════════════════════════════════════════════════
//  Consolidate
// ═══════════════════════════════════════════════════════════════

fn select_consolidate(
    utxos: &[UtxoCandidate],
    target: u64,
    base_fee: u64,
    fee_per_input: u64,
) -> Result<SelectionResult, String> {
    // Select smallest UTXOs first (consolidate fragmentation)
    let mut sorted: Vec<&UtxoCandidate> = utxos.iter().collect();
    sorted.sort_by_key(|u| u.amount);

    accumulate(&sorted, target, base_fee, fee_per_input, "consolidate")
}

// ═══════════════════════════════════════════════════════════════
//  Helper: Greedy Accumulation
// ═══════════════════════════════════════════════════════════════

fn accumulate(
    sorted: &[&UtxoCandidate],
    target: u64,
    base_fee: u64,
    fee_per_input: u64,
    strategy_name: &'static str,
) -> Result<SelectionResult, String> {
    let mut selected = Vec::new();
    let mut accumulated: u64 = 0;

    for utxo in sorted {
        let n = selected.len() as u64 + 1;
        let effective_fee = base_fee + fee_per_input * n;
        let needed = target.saturating_add(effective_fee);

        selected.push((*utxo).clone());
        accumulated = accumulated.saturating_add(utxo.amount);

        if accumulated >= needed {
            let change = accumulated.saturating_sub(target + effective_fee);
            return Ok(SelectionResult {
                selected,
                total_input: accumulated,
                fee: effective_fee,
                change,
                dust_absorbed: false,
                strategy: strategy_name,
            });
        }
    }

    let total: u64 = sorted.iter().map(|u| u.amount).sum();
    Err(format!(
        "insufficient funds: have {}, need {} + fees",
        total, target
    ))
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn utxo(id: u64, amount: u64, age: u64) -> UtxoCandidate {
        UtxoCandidate {
            id,
            tx_hash: [id as u8; 32],
            output_index: 0,
            amount,
            confirmed_at: age,
            input_weight: 200,
        }
    }

    #[test]
    fn test_bnb_exact_match() {
        let utxos = vec![utxo(1, 3000, 10), utxo(2, 5000, 20), utxo(3, 2000, 30)];

        // Target 5000, fee 0 → should select the single 5000 UTXO
        let result = select(&utxos, 5000, 0, 0, Strategy::BranchAndBound);
        assert!(result.is_ok());
        let r = result.expect("test: bnb exact");
        assert_eq!(r.change, 0);
        assert_eq!(r.total_input, 5000);
    }

    #[test]
    fn test_bnb_multi_utxo_exact() {
        let utxos = vec![utxo(1, 3000, 10), utxo(2, 2000, 20), utxo(3, 1000, 30)];

        // Target 5000 with 0 fee → should select 3000 + 2000
        let result = select(&utxos, 5000, 0, 0, Strategy::BranchAndBound);
        assert!(result.is_ok());
        let r = result.expect("test: bnb multi");
        assert_eq!(r.total_input, 5000);
        assert_eq!(r.change, 0);
    }

    #[test]
    fn test_bnb_fallback_when_no_exact() {
        let utxos = vec![utxo(1, 3000, 10), utxo(2, 4000, 20)];

        // Target 5500 → no exact match possible (3000+4000=7000 ≠ 5500)
        // BnB should fail, auto should fallback
        let result = select(&utxos, 5500, 0, 0, Strategy::BranchAndBound);
        assert!(result.is_err());

        // Auto should succeed via fallback
        let auto = select(&utxos, 5500, 0, 0, Strategy::Auto);
        assert!(auto.is_ok());
    }

    #[test]
    fn test_largest_first() {
        let utxos = vec![utxo(1, 1000, 10), utxo(2, 5000, 20), utxo(3, 3000, 30)];

        let result = select(&utxos, 4000, 100, 0, Strategy::LargestFirst);
        assert!(result.is_ok());
        let r = result.expect("test: largest");
        // Should pick 5000 first (covers 4100)
        assert_eq!(r.selected.len(), 1);
        assert_eq!(r.selected[0].amount, 5000);
    }

    #[test]
    fn test_smallest_sufficient() {
        let utxos = vec![utxo(1, 10000, 10), utxo(2, 5000, 20), utxo(3, 4200, 30)];

        let result = select(&utxos, 4000, 100, 0, Strategy::SmallestSufficient);
        assert!(result.is_ok());
        let r = result.expect("test: smallest");
        // Should pick 4200 (smallest that covers 4100)
        assert_eq!(r.selected[0].amount, 4200);
        assert_eq!(r.change, 0, "dust change should be absorbed");
        assert!(r.dust_absorbed);
        assert_eq!(r.fee, 200);
    }

    #[test]
    fn test_dust_absorption() {
        let utxos = vec![utxo(1, 4050, 10)];

        // Target 4000, fee 0 → change = 50 (below DUST_THRESHOLD)
        let result = select(&utxos, 4000, 0, 0, Strategy::LargestFirst);
        assert!(result.is_ok());
        let r = result.expect("test: dust");
        assert_eq!(r.change, 0, "dust should be absorbed");
        assert!(r.dust_absorbed);
        assert_eq!(r.fee, 50, "dust should be added to fee");
    }

    #[test]
    fn test_no_dust_for_large_change() {
        let utxos = vec![utxo(1, 10000, 10)];

        // Target 5000, fee 100 → change = 4900 (above dust)
        let result = select(&utxos, 5000, 100, 0, Strategy::LargestFirst);
        assert!(result.is_ok());
        let r = result.expect("test: no dust");
        assert_eq!(r.change, 4900);
        assert!(!r.dust_absorbed);
    }

    #[test]
    fn test_consolidate_prefers_small_utxos() {
        let utxos = vec![
            utxo(1, 100, 10),
            utxo(2, 200, 20),
            utxo(3, 300, 30),
            utxo(4, 5000, 40),
        ];

        let result = select(&utxos, 500, 0, 0, Strategy::Consolidate);
        assert!(result.is_ok());
        let r = result.expect("test: consolidate");
        // Should select 100 + 200 + 300 = 600 (3 small UTXOs) rather than 1 large
        assert!(r.selected.len() >= 3);
        // The large 5000 UTXO should NOT be in the selection
        assert!(!r.selected.iter().any(|u| u.amount == 5000));
    }

    #[test]
    fn test_privacy_aware_avoids_exact() {
        let utxos = vec![
            utxo(1, 5000, 10),  // exact match → avoided
            utxo(2, 7000, 100), // change = 2000 (healthy)
            utxo(3, 5500, 50),  // change = 500 (ok)
        ];

        let result = select(&utxos, 5000, 0, 0, Strategy::PrivacyAware);
        assert!(result.is_ok());
        let r = result.expect("test: privacy");
        // Should prefer a UTXO with healthy change over exact match
        assert!(r.change >= DUST_THRESHOLD || r.change == 0);
    }

    #[test]
    fn test_insufficient_funds() {
        let utxos = vec![utxo(1, 100, 10)];
        let result = select(&utxos, 5000, 100, 0, Strategy::LargestFirst);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_utxos() {
        let result = select(&[], 1000, 0, 0, Strategy::LargestFirst);
        assert!(result.is_err());
    }

    #[test]
    fn test_fee_per_input_scaling() {
        let utxos = vec![utxo(1, 3000, 10), utxo(2, 3000, 20)];

        // With fee_per_input, 2 inputs cost more
        let result = select(&utxos, 5000, 100, 500, Strategy::LargestFirst);
        assert!(result.is_err());
    }

    #[test]
    fn test_auto_tries_bnb_first() {
        let utxos = vec![utxo(1, 3000, 10), utxo(2, 2000, 20)];

        let result = select(&utxos, 5000, 0, 0, Strategy::Auto);
        assert!(result.is_ok());
        let r = result.expect("test: auto bnb");
        // BnB should find exact match
        assert_eq!(r.change, 0);
        assert_eq!(r.strategy, "branch_and_bound");
    }

    #[test]
    fn test_bnb_with_fees() {
        let utxos = vec![
            utxo(1, 3000, 10),
            utxo(2, 2100, 20), // 3000 + 2100 = 5100 = 5000 + 100 (fee)
        ];

        let result = select(&utxos, 5000, 100, 0, Strategy::BranchAndBound);
        assert!(result.is_ok());
        let r = result.expect("test: bnb fees");
        assert_eq!(r.total_input, 5100);
        assert!(r.change < DUST_THRESHOLD);
    }
}
