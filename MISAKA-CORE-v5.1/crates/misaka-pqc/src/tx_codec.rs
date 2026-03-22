//! Transaction Binary Codec — compact wire format.
//!
//! Encodes complete UTXO transactions into a compact binary format
//! suitable for network transmission and on-chain storage.
//!
//! # Wire Format (v1)
//!
//! ```text
//! [1B version]
//! [1B ring_scheme]
//! [opt: 1B marker=0xA1][opt: 1B tx_type]
//! [4B num_inputs]
//!   per input:
//!     [4B num_ring_members]
//!       per member: [32B tx_hash][4B output_index]
//!     [4B ring_sig_len][ring_sig_bytes (v2 compact)]
//!     [32B key_image]
//!     [4B ki_proof_len][ki_proof_bytes] (optional, 0 if absent)
//! [4B num_outputs]
//!   per output:
//!     [8B amount]
//!     [20B one_time_address (v1-v3) | 32B one_time_address (v4+)]
//!     [1B has_stealth]
//!       if 1: [stealth MCS-1 encoded]
//!     [opt: 1B has_spending_pubkey][opt: 4B len][opt: spending_pubkey]
//! [8B fee]
//! [4B extra_len][extra_bytes]
//! [opt trailing extension]
//!   [1B marker=0x5A][1B zk_backend_tag][4B zk_len][zk_proof_bytes]
//! ```

use misaka_types::stealth::PqStealthData;
use misaka_types::utxo::*;

/// Marker that indicates the extended wire format which preserves tx_type
/// and spending_pubkey. Chosen outside the realistic input-count range.
const WIRE_FORMAT_V2_MARKER: u8 = 0xA1;
/// Trailing extension marker for an optional transaction-level ZK proof.
const WIRE_ZK_PROOF_MARKER: u8 = 0x5A;

/// Encode a UTXO transaction to compact binary wire format.
pub fn encode_transaction(tx: &UtxoTransaction) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);

    // Version + ring scheme
    buf.push(tx.version);
    buf.push(tx.ring_scheme);
    buf.push(WIRE_FORMAT_V2_MARKER);
    buf.push(tx.tx_type.to_byte());

    // Inputs
    write_u32(&mut buf, tx.inputs.len() as u32);
    for inp in &tx.inputs {
        // Ring members
        write_u32(&mut buf, inp.ring_members.len() as u32);
        for m in &inp.ring_members {
            buf.extend_from_slice(&m.tx_hash);
            write_u32(&mut buf, m.output_index);
        }
        // Ring signature (raw bytes, caller can use v2 packing)
        write_u32(&mut buf, inp.ring_signature.len() as u32);
        buf.extend_from_slice(&inp.ring_signature);
        // Key image
        buf.extend_from_slice(&inp.key_image);
        // KI proof
        write_u32(&mut buf, inp.ki_proof.len() as u32);
        buf.extend_from_slice(&inp.ki_proof);
    }

    // Outputs
    write_u32(&mut buf, tx.outputs.len() as u32);
    for out in &tx.outputs {
        write_u64(&mut buf, out.amount);
        // v4+ (Q-DAG-CT): full 32-byte one_time_address
        // v1/v2/v3: legacy 20-byte one_time_address (first 20 bytes only)
        if tx.version >= UTXO_TX_VERSION_V4 {
            buf.extend_from_slice(&out.one_time_address);
        } else {
            buf.extend_from_slice(&out.one_time_address[..20]);
        }
        match &out.pq_stealth {
            Some(sd) => {
                buf.push(1);
                sd.mcs1_encode(&mut buf);
            }
            None => {
                buf.push(0);
            }
        }
        match &out.spending_pubkey {
            Some(pk) => {
                buf.push(1);
                write_u32(&mut buf, pk.len() as u32);
                buf.extend_from_slice(pk);
            }
            None => {
                buf.push(0);
            }
        }
    }

    // Fee
    write_u64(&mut buf, tx.fee);

    // Extra
    write_u32(&mut buf, tx.extra.len() as u32);
    buf.extend_from_slice(&tx.extra);

    if let Some(proof) = &tx.zk_proof {
        buf.push(WIRE_ZK_PROOF_MARKER);
        buf.push(proof.backend_tag);
        write_u32(&mut buf, proof.proof_bytes.len() as u32);
        buf.extend_from_slice(&proof.proof_bytes);
    }

    buf
}

/// Decode a UTXO transaction from binary wire format.
pub fn decode_transaction(data: &[u8]) -> Result<UtxoTransaction, String> {
    let mut off = 0;

    let version = read_u8(data, &mut off)?;
    let ring_scheme = if off < data.len() {
        read_u8(data, &mut off)?
    } else {
        0x01 // default LRS for legacy wire format
    };
    let has_extended_fields = off < data.len() && data[off] == WIRE_FORMAT_V2_MARKER;
    let tx_type = if has_extended_fields {
        off += 1;
        let raw = read_u8(data, &mut off)?;
        TxType::from_byte(raw).ok_or_else(|| format!("invalid tx_type byte: {}", raw))?
    } else {
        TxType::Transfer
    };

    // Inputs
    let n_inputs = read_u32(data, &mut off)? as usize;
    let mut inputs = Vec::with_capacity(n_inputs);
    for _ in 0..n_inputs {
        let n_members = read_u32(data, &mut off)? as usize;
        let mut ring_members = Vec::with_capacity(n_members);
        for _ in 0..n_members {
            let mut tx_hash = [0u8; 32];
            read_fixed(data, &mut off, &mut tx_hash)?;
            let output_index = read_u32(data, &mut off)?;
            ring_members.push(OutputRef {
                tx_hash,
                output_index,
            });
        }
        let sig_len = read_u32(data, &mut off)? as usize;
        let ring_signature = read_bytes(data, &mut off, sig_len)?;
        let mut key_image = [0u8; 32];
        read_fixed(data, &mut off, &mut key_image)?;
        let ki_proof_len = read_u32(data, &mut off)? as usize;
        let ki_proof = read_bytes(data, &mut off, ki_proof_len)?;

        inputs.push(RingInput {
            ring_members,
            ring_signature,
            key_image,
            ki_proof,
        });
    }

    // Outputs
    let n_outputs = read_u32(data, &mut off)? as usize;
    let mut outputs = Vec::with_capacity(n_outputs);
    for _ in 0..n_outputs {
        let amount = read_u64(data, &mut off)?;
        // v4+ (Q-DAG-CT): full 32-byte one_time_address
        // v1/v2/v3: legacy 20-byte one_time_address, zero-padded to 32
        let mut one_time_address = [0u8; 32];
        if version >= UTXO_TX_VERSION_V4 {
            read_fixed(data, &mut off, &mut one_time_address)?;
        } else {
            let mut legacy = [0u8; 20];
            read_fixed(data, &mut off, &mut legacy)?;
            one_time_address[..20].copy_from_slice(&legacy);
        }
        let has_stealth = read_u8(data, &mut off)?;
        let pq_stealth = if has_stealth == 1 {
            Some(
                PqStealthData::mcs1_decode(data, &mut off)
                    .map_err(|e| format!("stealth decode: {}", e))?,
            )
        } else {
            None
        };
        let spending_pubkey = if has_extended_fields {
            let has_spending_pubkey = read_u8(data, &mut off)?;
            if has_spending_pubkey == 1 {
                let len = read_u32(data, &mut off)? as usize;
                Some(read_bytes(data, &mut off, len)?)
            } else {
                None
            }
        } else {
            None
        };
        outputs.push(TxOutput {
            amount,
            one_time_address,
            pq_stealth,
            spending_pubkey,
        });
    }

    // Fee
    let fee = read_u64(data, &mut off)?;

    // Extra
    let extra_len = read_u32(data, &mut off)? as usize;
    let extra = read_bytes(data, &mut off, extra_len)?;

    let zk_proof = if off < data.len() {
        let marker = read_u8(data, &mut off)?;
        if marker != WIRE_ZK_PROOF_MARKER {
            return Err(format!(
                "unknown trailing tx extension marker: 0x{:02x}",
                marker
            ));
        }
        let backend_tag = read_u8(data, &mut off)?;
        let proof_len = read_u32(data, &mut off)? as usize;
        Some(ZeroKnowledgeProofCarrier {
            backend_tag,
            proof_bytes: read_bytes(data, &mut off, proof_len)?,
        })
    } else {
        None
    };

    if off != data.len() {
        return Err(format!(
            "trailing {} undecoded bytes after tx decode",
            data.len() - off
        ));
    }

    Ok(UtxoTransaction {
        version,
        ring_scheme,
        tx_type,
        inputs,
        outputs,
        fee,
        extra,
        zk_proof,
    })
}

/// Compute wire size without actually encoding.
pub fn wire_size(tx: &UtxoTransaction) -> usize {
    let mut sz = 1 + 1 + 1 + 1 + 4; // version + ring_scheme + marker + tx_type + num_inputs
    for inp in &tx.inputs {
        sz += 4; // num_ring_members
        sz += inp.ring_members.len() * 36; // 32 + 4 per member
        sz += 4 + inp.ring_signature.len(); // sig
        sz += 32; // key image
        sz += 4 + inp.ki_proof.len(); // ki proof
    }
    sz += 4; // num_outputs
    for out in &tx.outputs {
        sz += 8 + 20 + 1; // amount + addr + has_stealth
        if let Some(sd) = &out.pq_stealth {
            sz += sd.wire_len();
        }
        sz += 1; // has_spending_pubkey
        if let Some(pk) = &out.spending_pubkey {
            sz += 4 + pk.len();
        }
    }
    sz += 8; // fee
    sz += 4 + tx.extra.len(); // extra
    if let Some(proof) = &tx.zk_proof {
        sz += 1 + 1 + 4 + proof.proof_bytes.len();
    }
    sz
}

// ─── Helpers ─────────────────────────────────────────────────

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn write_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn read_u8(data: &[u8], off: &mut usize) -> Result<u8, String> {
    if *off >= data.len() {
        return Err("EOF".into());
    }
    let v = data[*off];
    *off += 1;
    Ok(v)
}

fn read_u32(data: &[u8], off: &mut usize) -> Result<u32, String> {
    if *off + 4 > data.len() {
        return Err("EOF".into());
    }
    let v = u32::from_le_bytes(
        data[*off..*off + 4]
            .try_into()
            .map_err(|_| "u32 slice".to_string())?,
    );
    *off += 4;
    Ok(v)
}

fn read_u64(data: &[u8], off: &mut usize) -> Result<u64, String> {
    if *off + 8 > data.len() {
        return Err("EOF".into());
    }
    let v = u64::from_le_bytes(
        data[*off..*off + 8]
            .try_into()
            .map_err(|_| "u64 slice".to_string())?,
    );
    *off += 8;
    Ok(v)
}

fn read_fixed(data: &[u8], off: &mut usize, out: &mut [u8]) -> Result<(), String> {
    if *off + out.len() > data.len() {
        return Err("EOF".into());
    }
    out.copy_from_slice(&data[*off..*off + out.len()]);
    *off += out.len();
    Ok(())
}

fn read_bytes(data: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    if *off + len > data.len() {
        return Err("EOF".into());
    }
    let v = data[*off..*off + len].to_vec();
    *off += len;
    Ok(v)
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packing::pack_ring_sig_v2;
    use crate::pq_kem::ml_kem_keygen;
    use crate::pq_ring::*;
    use crate::pq_sign::MlDsaKeypair;
    use crate::pq_stealth::create_stealth_output;
    use misaka_types::stealth::PQ_STEALTH_VERSION;

    #[test]
    fn test_encode_decode_simple_tx() {
        let tx = UtxoTransaction {
            ring_scheme: RING_SCHEME_LRS,
            tx_type: TxType::Transfer,
            version: UTXO_TX_VERSION,
            inputs: vec![RingInput {
                ring_members: vec![
                    OutputRef {
                        tx_hash: [0x01; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [0x02; 32],
                        output_index: 1,
                    },
                    OutputRef {
                        tx_hash: [0x03; 32],
                        output_index: 2,
                    },
                    OutputRef {
                        tx_hash: [0x04; 32],
                        output_index: 3,
                    },
                ],
                ring_signature: vec![0xAA; 200],
                key_image: [0xBB; 32],
                ki_proof: vec![0xDD; 100],
            }],
            outputs: vec![TxOutput {
                amount: 5000,
                one_time_address: [0xCC; 32],
                pq_stealth: None,
                spending_pubkey: Some(vec![0x99; 48]),
            }],
            fee: 100,
            extra: b"hello".to_vec(),
            zk_proof: None,
        };

        let encoded = encode_transaction(&tx);
        let decoded = decode_transaction(&encoded).unwrap();

        assert_eq!(decoded.version, tx.version);
        assert_eq!(decoded.inputs.len(), 1);
        assert_eq!(decoded.inputs[0].ring_members.len(), 4);
        assert_eq!(decoded.inputs[0].key_image, [0xBB; 32]);
        assert_eq!(decoded.tx_type, TxType::Transfer);
        assert_eq!(decoded.outputs[0].amount, 5000);
        assert_eq!(decoded.outputs[0].spending_pubkey, Some(vec![0x99; 48]));
        assert_eq!(decoded.fee, 100);
        assert_eq!(decoded.extra, b"hello");
    }

    #[test]
    fn test_encode_decode_with_stealth() {
        let kem_kp = ml_kem_keygen().unwrap();
        let tx_id = [0x42; 32];
        let stealth = create_stealth_output(&kem_kp.public_key, 7777, b"memo", &tx_id, 0).unwrap();

        let tx = UtxoTransaction {
            ring_scheme: RING_SCHEME_LRS,
            tx_type: TxType::Transfer,
            version: UTXO_TX_VERSION,
            inputs: vec![RingInput {
                ring_members: vec![
                    OutputRef {
                        tx_hash: [1; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [2; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [3; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [4; 32],
                        output_index: 0,
                    },
                ],
                ring_signature: vec![0xAA; 100],
                key_image: [0xBB; 32],
                ki_proof: vec![0xDD; 80],
            }],
            outputs: vec![TxOutput {
                amount: 7777,
                one_time_address: stealth.one_time_address,
                pq_stealth: Some(stealth.stealth_data),
                spending_pubkey: Some(vec![0x55; 48]),
            }],
            fee: 50,
            extra: vec![],
            zk_proof: None,
        };

        let encoded = encode_transaction(&tx);
        let decoded = decode_transaction(&encoded).unwrap();

        assert_eq!(decoded.outputs[0].amount, 7777);
        assert!(decoded.outputs[0].pq_stealth.is_some());
        let sd = decoded.outputs[0].pq_stealth.as_ref().unwrap();
        assert_eq!(sd.version, PQ_STEALTH_VERSION);
        assert_eq!(sd.kem_ct.len(), 1088);
        assert_eq!(decoded.outputs[0].spending_pubkey, Some(vec![0x55; 48]));
    }

    #[test]
    fn test_full_tx_with_real_ring_sig() {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let kps: Vec<SpendingKeypair> = (0..4)
            .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap())
            .collect();
        let ring_pks: Vec<Poly> = kps.iter().map(|k| k.public_poly.clone()).collect();

        let kem_kp = ml_kem_keygen().unwrap();
        let tx_id = [0x99; 32];
        let stealth =
            create_stealth_output(&kem_kp.public_key, 10000, b"real tx", &tx_id, 0).unwrap();

        // Use strong-binding canonical key image for ki_proof
        let (_, strong_ki) =
            crate::ki_proof::canonical_strong_ki(&kps[1].public_poly, &kps[1].secret_poly);

        let mut tx = UtxoTransaction {
            ring_scheme: RING_SCHEME_LRS,
            tx_type: TxType::Transfer,
            version: UTXO_TX_VERSION,
            inputs: vec![RingInput {
                ring_members: vec![
                    OutputRef {
                        tx_hash: [0x01; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [0x02; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [0x03; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [0x04; 32],
                        output_index: 0,
                    },
                ],
                ring_signature: vec![],
                key_image: strong_ki,
                ki_proof: vec![],
            }],
            outputs: vec![
                TxOutput {
                    amount: 9500,
                    one_time_address: stealth.one_time_address,
                    pq_stealth: Some(stealth.stealth_data),
                    spending_pubkey: Some(vec![0xAB; 48]),
                },
                TxOutput {
                    amount: 400,
                    one_time_address: [0xDD; 32],
                    pq_stealth: None,
                    spending_pubkey: Some(vec![0xCD; 48]),
                },
            ],
            fee: 100,
            extra: vec![],
            zk_proof: None,
        };

        // Sign
        let digest = tx.signing_digest();
        let sig = ring_sign(&a, &ring_pks, 1, &kps[1].secret_poly, &digest).unwrap();

        // Use v2 compact packing
        tx.inputs[0].ring_signature = pack_ring_sig_v2(&sig);
        let kip = crate::ki_proof::prove_key_image(
            &a,
            &kps[1].secret_poly,
            &kps[1].public_poly,
            &strong_ki,
        )
        .unwrap();
        tx.inputs[0].ki_proof = kip.to_bytes();

        // Encode → Decode roundtrip
        let wire_bytes = encode_transaction(&tx);
        let decoded = decode_transaction(&wire_bytes).unwrap();

        // Compare
        assert_eq!(decoded.signing_digest(), tx.signing_digest());
        assert_eq!(decoded.inputs[0].key_image, strong_ki);
        assert_eq!(decoded.outputs[0].amount, 9500);
        assert_eq!(decoded.outputs[0].spending_pubkey, Some(vec![0xAB; 48]));
        assert_eq!(decoded.outputs[1].spending_pubkey, Some(vec![0xCD; 48]));
        assert_eq!(decoded.fee, 100);

        // Unpack ring sig from decoded tx and verify
        let decoded_sig =
            crate::packing::unpack_ring_sig_v2(&decoded.inputs[0].ring_signature, 4).unwrap();
        ring_verify(&a, &ring_pks, &digest, &decoded_sig).unwrap();

        println!("\n  ═══ Real TX Wire Size Breakdown ═══");
        println!("  Total wire:    {} bytes", wire_bytes.len());
        println!(
            "  Ring sig (v2): {} bytes",
            tx.inputs[0].ring_signature.len()
        );
        println!(
            "  Stealth data:  {} bytes",
            tx.outputs[0].pq_stealth.as_ref().unwrap().wire_len()
        );
        println!(
            "  Overhead:      {} bytes (headers/refs/amounts)",
            wire_bytes.len()
                - tx.inputs[0].ring_signature.len()
                - tx.outputs[0].pq_stealth.as_ref().unwrap().wire_len()
        );

        let raw_sig_size = sig.to_bytes().len();
        println!(
            "\n  Sig compression: {} → {} bytes ({:.1}% saved)",
            raw_sig_size,
            tx.inputs[0].ring_signature.len(),
            (1.0 - tx.inputs[0].ring_signature.len() as f64 / raw_sig_size as f64) * 100.0
        );
    }

    #[test]
    fn test_wire_size_matches() {
        let tx = UtxoTransaction {
            ring_scheme: RING_SCHEME_LRS,
            tx_type: TxType::Transfer,
            version: UTXO_TX_VERSION,
            inputs: vec![RingInput {
                ring_members: vec![
                    OutputRef {
                        tx_hash: [1; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [2; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [3; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [4; 32],
                        output_index: 0,
                    },
                ],
                ring_signature: vec![0; 1900],
                key_image: [0; 32],
                ki_proof: vec![0; 200],
            }],
            outputs: vec![TxOutput {
                amount: 1000,
                one_time_address: [0; 32],
                pq_stealth: None,
                spending_pubkey: Some(vec![0x77; 48]),
            }],
            fee: 10,
            extra: vec![1, 2, 3],
            zk_proof: None,
        };

        let encoded = encode_transaction(&tx);
        assert_eq!(encoded.len(), wire_size(&tx));
    }

    #[test]
    fn test_codec_preserves_non_transfer_tx_type() {
        let tx = UtxoTransaction {
            ring_scheme: RING_SCHEME_LOGRING,
            tx_type: TxType::Faucet,
            version: UTXO_TX_VERSION_V3,
            inputs: vec![],
            outputs: vec![TxOutput {
                amount: 123,
                one_time_address: [0x12; 32],
                pq_stealth: None,
                spending_pubkey: Some(vec![0x34; 48]),
            }],
            fee: 0,
            extra: b"faucet".to_vec(),
            zk_proof: None,
        };

        let encoded = encode_transaction(&tx);
        let decoded = decode_transaction(&encoded).unwrap();
        assert_eq!(decoded.tx_type, TxType::Faucet);
        assert_eq!(decoded.outputs[0].spending_pubkey, Some(vec![0x34; 48]));
        assert_eq!(decoded.signing_digest(), tx.signing_digest());
    }

    #[test]
    fn test_decode_legacy_wire_defaults_transfer_and_no_spending_pubkey() {
        fn encode_legacy(tx: &UtxoTransaction) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.push(tx.version);
            buf.push(tx.ring_scheme);
            write_u32(&mut buf, tx.inputs.len() as u32);
            for inp in &tx.inputs {
                write_u32(&mut buf, inp.ring_members.len() as u32);
                for m in &inp.ring_members {
                    buf.extend_from_slice(&m.tx_hash);
                    write_u32(&mut buf, m.output_index);
                }
                write_u32(&mut buf, inp.ring_signature.len() as u32);
                buf.extend_from_slice(&inp.ring_signature);
                buf.extend_from_slice(&inp.key_image);
                write_u32(&mut buf, inp.ki_proof.len() as u32);
                buf.extend_from_slice(&inp.ki_proof);
            }
            write_u32(&mut buf, tx.outputs.len() as u32);
            for out in &tx.outputs {
                write_u64(&mut buf, out.amount);
                buf.extend_from_slice(&out.one_time_address[..20]);
                match &out.pq_stealth {
                    Some(sd) => {
                        buf.push(1);
                        sd.mcs1_encode(&mut buf);
                    }
                    None => buf.push(0),
                }
            }
            write_u64(&mut buf, tx.fee);
            write_u32(&mut buf, tx.extra.len() as u32);
            buf.extend_from_slice(&tx.extra);
            buf
        }

        let tx = UtxoTransaction {
            ring_scheme: RING_SCHEME_LRS,
            tx_type: TxType::Transfer,
            version: UTXO_TX_VERSION,
            inputs: vec![RingInput {
                ring_members: vec![
                    OutputRef {
                        tx_hash: [0x01; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [0x02; 32],
                        output_index: 1,
                    },
                    OutputRef {
                        tx_hash: [0x03; 32],
                        output_index: 2,
                    },
                    OutputRef {
                        tx_hash: [0x04; 32],
                        output_index: 3,
                    },
                ],
                ring_signature: vec![0xAA; 32],
                key_image: [0xBB; 32],
                ki_proof: vec![0xCC; 16],
            }],
            outputs: vec![TxOutput {
                amount: 99,
                one_time_address: [0xDD; 32],
                pq_stealth: None,
                spending_pubkey: Some(vec![0xEE; 48]),
            }],
            fee: 7,
            extra: b"legacy".to_vec(),
            zk_proof: None,
        };

        let decoded = decode_transaction(&encode_legacy(&tx)).unwrap();
        assert_eq!(decoded.tx_type, TxType::Transfer);
        assert_eq!(decoded.outputs[0].spending_pubkey, None);
        assert_eq!(decoded.outputs[0].amount, tx.outputs[0].amount);
        assert_eq!(decoded.zk_proof, None);
    }

    #[test]
    fn test_encode_decode_with_zk_proof_carrier() {
        let tx = UtxoTransaction {
            ring_scheme: RING_SCHEME_LOGRING,
            tx_type: TxType::Transfer,
            version: UTXO_TX_VERSION_V3,
            inputs: vec![],
            outputs: vec![TxOutput {
                amount: 123,
                one_time_address: [0x12; 32],
                pq_stealth: None,
                spending_pubkey: Some(vec![0x34; 48]),
            }],
            fee: 0,
            extra: b"zk".to_vec(),
            zk_proof: Some(ZeroKnowledgeProofCarrier {
                backend_tag: 0xF1,
                proof_bytes: vec![0xAB; 64],
            }),
        };

        let encoded = encode_transaction(&tx);
        let decoded = decode_transaction(&encoded).unwrap();
        assert_eq!(decoded.zk_proof, tx.zk_proof);
        assert_eq!(encoded.len(), wire_size(&tx));
    }
}
