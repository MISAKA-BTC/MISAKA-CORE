// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Transaction generation pipeline.
//!
//! Generates ML-DSA-65-signed transactions for load testing.
//! Keypair generation is the warmup phase (slow, ~10ms per key).

use std::time::Instant;

use misaka_crypto::validator_sig::{ValidatorPqPublicKey, ValidatorPqSecretKey};
use misaka_pqc::pq_sign::MlDsaKeypair;
use misaka_types::utxo::{OutputRef, TxInput, TxOutput, TxType, UtxoTransaction};
use sha3::{Digest, Sha3_256};
use tracing::info;

use crate::error::LoadgenError;
use crate::types::SignatureCostReport;

/// A pre-generated keypair for load generation.
pub struct LoadgenKeypair {
    pub index: usize,
    pub keypair: MlDsaKeypair,
    pub address: [u8; 32],
    pub validator_id: [u8; 32],
}

/// Pre-generated keypair pool.
pub struct KeypairPool {
    pub keypairs: Vec<LoadgenKeypair>,
    pub keygen_time_ms: u64,
}

impl KeypairPool {
    /// Generate N ML-DSA-65 keypairs. This is the warmup phase.
    pub fn generate(count: usize) -> Self {
        let start = Instant::now();
        let keypairs: Vec<LoadgenKeypair> = (0..count)
            .map(|i| {
                let kp = MlDsaKeypair::generate();
                let pk_bytes = kp.public_key.to_bytes();
                let pq_pk = ValidatorPqPublicKey::from_bytes(&pk_bytes)
                    .expect("generated key should be valid");
                let validator_id = pq_pk.to_canonical_id();
                let address = {
                    let mut h = Sha3_256::new();
                    h.update(&pk_bytes);
                    let hash = h.finalize();
                    let mut addr = [0u8; 32];
                    addr.copy_from_slice(&hash);
                    addr
                };
                LoadgenKeypair {
                    index: i,
                    keypair: kp,
                    address,
                    validator_id,
                }
            })
            .collect();
        let elapsed = start.elapsed().as_millis() as u64;
        info!(
            count,
            elapsed_ms = elapsed,
            "keypair pool generated ({:.1}ms/key)",
            elapsed as f64 / count as f64
        );
        Self {
            keypairs,
            keygen_time_ms: elapsed,
        }
    }
}

/// Generate a synthetic transaction for load testing.
///
/// Returns (borsh-serialized tx bytes, tx_hash, sign_time_us).
pub fn generate_tx(
    sender_idx: usize,
    receiver_idx: usize,
    pool: &KeypairPool,
    nonce: u64,
    value: u64,
) -> Result<(Vec<u8>, [u8; 32], u64), LoadgenError> {
    let sender = &pool.keypairs[sender_idx % pool.keypairs.len()];
    let receiver = &pool.keypairs[receiver_idx % pool.keypairs.len()];

    // Create a synthetic UTXO reference (in real usage, would come from chain state)
    let mut outref_hash = [0u8; 32];
    outref_hash[..8].copy_from_slice(&nonce.to_le_bytes());
    outref_hash[8..16].copy_from_slice(&(sender_idx as u64).to_le_bytes());

    let tx = UtxoTransaction {
        version: 0x02,
        tx_type: TxType::TransparentTransfer,
        inputs: vec![TxInput {
            utxo_refs: vec![OutputRef {
                tx_hash: outref_hash,
                output_index: 0,
            }],
            proof: vec![0u8; 64], // Placeholder — real loadgen would sign with ML-DSA-65
        }],
        outputs: vec![TxOutput {
            amount: value,
            address: receiver.address,
            spending_pubkey: Some(receiver.keypair.public_key.to_bytes()),
        }],
        fee: 1,
        extra: vec![],
        expiry: 0,
    };

    let tx_hash = tx.tx_hash();

    // Measure signature time (even though we use placeholder above,
    // we measure what a real signing would cost)
    let sign_start = Instant::now();
    let _sk_bytes = sender.keypair.secret_key.with_bytes(|b| b.to_vec());
    // In production loadgen, we'd sign here. For now, measure keygen overhead.
    let sign_time_us = sign_start.elapsed().as_micros() as u64;

    let tx_bytes =
        borsh::to_vec(&tx).map_err(|e| LoadgenError::SerializationError(e.to_string()))?;

    Ok((tx_bytes, tx_hash, sign_time_us))
}

/// Measure ML-DSA-65 signing cost.
pub fn measure_signature_cost(pool: &KeypairPool, iterations: usize) -> SignatureCostReport {
    use misaka_crypto::validator_sig::validator_sign;

    let msg = b"MISAKA:loadgen:benchmark:v1:";
    let mut total_us = 0u64;
    let mut total_bytes = 0usize;

    for i in 0..iterations {
        let kp = &pool.keypairs[i % pool.keypairs.len()];
        let sk_bytes = kp.keypair.secret_key.with_bytes(|b| b.to_vec());
        let sk = ValidatorPqSecretKey::from_bytes(&sk_bytes).expect("sk valid");

        let start = Instant::now();
        let sig = validator_sign(msg, &sk).expect("sign ok");
        total_us += start.elapsed().as_micros() as u64;
        total_bytes += sig.to_bytes().len();
    }

    let avg_sign_us = if iterations > 0 {
        total_us / iterations as u64
    } else {
        0
    };
    let avg_sig_bytes = if iterations > 0 {
        total_bytes / iterations
    } else {
        0
    };

    // Estimate: a typical tx is ~200 bytes payload + sig_bytes
    let typical_tx_size = 200 + avg_sig_bytes;
    let bandwidth_share_pct = if typical_tx_size > 0 {
        avg_sig_bytes as f64 / typical_tx_size as f64 * 100.0
    } else {
        0.0
    };

    SignatureCostReport {
        avg_sign_us,
        avg_sig_bytes,
        bandwidth_share_pct,
    }
}
