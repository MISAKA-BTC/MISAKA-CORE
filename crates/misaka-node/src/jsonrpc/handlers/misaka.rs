use super::HandlerResult;
use crate::dag_rpc::DagRpcState;
use crate::jsonrpc::error::*;
use misaka_dag::compute_epoch;
use serde_json::{json, Value};

const ZERO_HASH_BYTES: [u8; 32] = [0u8; 32];

// ═══════════════════════════════════════════════════════════════
//  DAG Info / Tips / Block
// ═══════════════════════════════════════════════════════════════

/// `misaka_getDagInfo` — comprehensive DAG metrics.
pub async fn get_dag_info(rpc: &DagRpcState) -> HandlerResult {
    let guard = rpc.node.read().await;
    let s = &*guard;
    crate::dag_rpc::sync_runtime_recovery_from_shadow_state(s, rpc.runtime_recovery.as_ref()).await;
    let (current_checkpoint_votes, vote_pool) = crate::dag_rpc::checkpoint_vote_pool_json(s);
    let runtime_recovery =
        crate::dag_rpc::dag_runtime_recovery_json(rpc.runtime_recovery.as_ref()).await;
    let validator_lifecycle_recovery =
        crate::dag_rpc::validator_lifecycle_recovery_json(rpc.runtime_recovery.as_ref()).await;
    let consensus_architecture = crate::dag_rpc::dag_consensus_architecture_json();
    let tx_dissemination =
        crate::dag_rpc::dag_tx_dissemination_json(s, rpc.narwhal_dissemination.as_ref());
    let ordering_contract =
        crate::dag_rpc::dag_ordering_contract_json(s, rpc.narwhal_dissemination.as_ref());
    let sr21_committee = crate::dag_rpc::dag_sr21_committee_json(s);
    let authority_switch_readiness = crate::dag_rpc::dag_authority_switch_readiness_json(
        &consensus_architecture,
        &ordering_contract,
        &sr21_committee,
        &runtime_recovery,
    );
    let validator_attestation =
        crate::dag_rpc::dag_validator_attestation_json(s, current_checkpoint_votes, vote_pool);
    let consumer_surfaces = crate::dag_rpc::dag_consumer_surfaces_json(s);
    let snapshot = s.dag_store.snapshot();
    let tips = snapshot.get_tips();

    Ok(json!({
        "consensusArchitecture": consensus_architecture,
        "txDissemination": tx_dissemination,
        "orderingContract": ordering_contract,
        "ghostdagK": s.ghostdag.k,
        "genesisHash": hex::encode(s.genesis_hash),
        "maxBlueScore": s.dag_store.max_blue_score(),
        "blockCount": s.dag_store.block_count(),
        "tipCount": tips.len(),
        "tips": tips.iter().map(|t| hex::encode(&t[..8])).collect::<Vec<_>>(),
        "blocksProduced": s.blocks_produced,
        "stateManager": {
            "applied": s.state_manager.stats.txs_applied,
            "failedKi": s.state_manager.stats.txs_failed_ki_conflict,
            "failedSig": s.state_manager.stats.txs_failed_invalid_sig,
            "coinbase": s.state_manager.stats.txs_coinbase,
            "totalFees": s.state_manager.stats.total_fees,
        },
        "validatorCount": s.validator_count,
        "validatorAttestation": validator_attestation,
        "sr21Committee": sr21_committee,
        "authoritySwitchReadiness": authority_switch_readiness,
        "latestCheckpoint": s.latest_checkpoint.as_ref().map(crate::dag_rpc::latest_checkpoint_json),
        "runtimeRecovery": runtime_recovery,
        "validatorLifecycleRecovery": validator_lifecycle_recovery,
        "consumerSurfaces": consumer_surfaces,
    }))
}

/// `misaka_getDagTips` — current DAG tips.
pub async fn get_dag_tips(rpc: &DagRpcState) -> HandlerResult {
    let s = rpc.node.read().await;
    let snapshot = s.dag_store.snapshot();
    let tips = snapshot.get_tips();

    let tip_info: Vec<Value> = tips
        .iter()
        .map(|tip_hash| {
            let score = snapshot
                .get_ghostdag_data(tip_hash)
                .map(|d| d.blue_score)
                .unwrap_or(0);
            json!({
                "hash": hex::encode(tip_hash),
                "blueScore": score,
            })
        })
        .collect();

    Ok(json!({ "tips": tip_info }))
}

/// `misaka_getDagBlock` — look up a DAG block by hash.
pub async fn get_dag_block(rpc: &DagRpcState, params: &Value) -> HandlerResult {
    let hash_hex = params.get(0).and_then(|v| v.as_str()).ok_or_else(|| {
        (
            INVALID_PARAMS,
            "params[0]: expected block hash hex".into(),
            None,
        )
    })?;

    let hash_bytes: [u8; 32] = hex::decode(hash_hex)
        .map_err(|e| (INVALID_PARAMS, format!("invalid hex: {}", e), None))?
        .try_into()
        .map_err(|_| (INVALID_PARAMS, "hash must be 32 bytes".into(), None))?;

    let s = rpc.node.read().await;
    let snapshot = s.dag_store.snapshot();

    let header = snapshot.get_header(&hash_bytes).ok_or_else(|| {
        (
            BLOCK_NOT_FOUND,
            format!("block {} not found", hash_hex),
            None,
        )
    })?;
    let ghostdag = snapshot.get_ghostdag_data(&hash_bytes);
    let txs = s.dag_store.get_block_txs(&hash_bytes);

    Ok(json!({
        "hash": hash_hex,
        "version": header.version,
        "parents": header.parents.iter().map(hex::encode).collect::<Vec<_>>(),
        "timestampMs": header.timestamp_ms,
        "txRoot": hex::encode(header.tx_root),
        "proposerId": hex::encode(header.proposer_id),
        "blueScore": header.blue_score,
        "ghostdag": ghostdag.map(|d| json!({
            "selectedParent": hex::encode(d.selected_parent),
            "mergesetBlues": d.mergeset_blues.len(),
            "mergesetReds": d.mergeset_reds.len(),
            "blueScore": d.blue_score,
        })),
        "txCount": txs.len(),
        "txHashes": txs.iter().map(|tx| hex::encode(tx.tx_hash())).collect::<Vec<_>>(),
    }))
}

// ═══════════════════════════════════════════════════════════════
//  Virtual Chain / State
// ═══════════════════════════════════════════════════════════════

/// `misaka_getVirtualChain` — chain changes from a start hash to virtual tip.
pub async fn get_virtual_chain(rpc: &DagRpcState, params: &Value) -> HandlerResult {
    let start_hash_hex = params.get(0).and_then(|v| v.as_str());

    let s = rpc.node.read().await;
    let snapshot = s.dag_store.snapshot();
    let tips = snapshot.get_tips();

    if tips.is_empty() {
        return Ok(json!({
            "virtualTip": null,
            "addedChainHashes": [],
            "removedChainHashes": [],
        }));
    }

    let virtual_sp = s.ghostdag.select_parent_public(&tips, &snapshot);

    let start_hash: Option<[u8; 32]> = match start_hash_hex {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str)
                .map_err(|e| (INVALID_PARAMS, format!("invalid hex: {}", e), None))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| (INVALID_PARAMS, "hash must be 32 bytes".into(), None))?;
            Some(arr)
        }
        None => None,
    };

    // Walk SP chain back to start_hash or genesis
    let mut sp_chain = Vec::new();
    let mut current = virtual_sp;
    loop {
        sp_chain.push(current);
        if Some(current) == start_hash {
            break;
        }
        if current == s.genesis_hash || current == ZERO_HASH_BYTES {
            break;
        }
        match snapshot.get_ghostdag_data(&current) {
            Some(data) if data.selected_parent != ZERO_HASH_BYTES => {
                current = data.selected_parent;
            }
            _ => break,
        }
    }
    sp_chain.reverse();

    if start_hash.is_some() && !sp_chain.is_empty() && Some(sp_chain[0]) == start_hash {
        sp_chain.remove(0);
    }

    Ok(json!({
        "virtualTip": hex::encode(virtual_sp),
        "addedChainHashes": sp_chain.iter().map(hex::encode).collect::<Vec<_>>(),
        "removedChainHashes": [],
    }))
}

/// `misaka_getVirtualState` — virtual state snapshot.
pub async fn get_virtual_state(rpc: &DagRpcState) -> HandlerResult {
    let s = rpc.node.read().await;
    let vs = &s.virtual_state;
    let snapshot = vs.snapshot();

    Ok(json!({
        "tip": hex::encode(snapshot.tip),
        "tipScore": snapshot.tip_score,
        "spend_tagCount": snapshot.spent_count,
        "utxoCount": snapshot.utxo_count,
        "stateRoot": hex::encode(snapshot.state_root),
        "createdAtMs": snapshot.created_at_ms,
        "stats": {
            "blocksApplied": vs.stats.blocks_applied,
            "spcSwitches": vs.stats.spc_switches,
            "reorgs": vs.stats.reorgs,
            "deepestReorg": vs.stats.deepest_reorg,
        },
    }))
}

// ═══════════════════════════════════════════════════════════════
//  Supply / Checkpoint / Protocol
// ═══════════════════════════════════════════════════════════════

/// `misaka_getCirculatingSupply` — total amount in UTXO set.
pub async fn get_circulating_supply(rpc: &DagRpcState) -> HandlerResult {
    let s = rpc.node.read().await;
    Ok(json!({
        "utxo_set_total": s.utxo_set.total_amount(),
        "note": "staked/burned not separately tracked in v1.0",
    }))
}

/// `misaka_getCheckpoint` — latest finalized checkpoint.
pub async fn get_checkpoint(rpc: &DagRpcState) -> HandlerResult {
    let s = rpc.node.read().await;
    match &s.latest_checkpoint {
        Some(cp) => {
            let target = cp.validator_target();
            Ok(json!({
                "blockHash": hex::encode(cp.block_hash),
                "blueScore": cp.blue_score,
                "utxoRoot": hex::encode(cp.utxo_root),
                "totalSpentCount": cp.total_spent_count,
                "totalAppliedTxs": cp.total_applied_txs,
                "timestampMs": cp.timestamp_ms,
                "validatorTarget": {
                    "blockHash": hex::encode(target.block_hash),
                    "blueScore": target.blue_score,
                    "utxoRoot": hex::encode(target.utxo_root),
                    "totalSpentCount": target.total_spent_count,
                    "totalAppliedTxs": target.total_applied_txs,
                },
            }))
        }
        None => Ok(Value::Null),
    }
}

/// `misaka_getProtocolVersion` — static protocol metadata.
pub async fn get_protocol_version(rpc: &DagRpcState) -> HandlerResult {
    let s = rpc.node.read().await;
    Ok(json!({
        "node_version": env!("CARGO_PKG_VERSION"),
        "protocol_version": 1,
        "chain_id": s.chain_id,
    }))
}

/// `misaka_getEpochInfo` — current epoch information.
pub async fn get_epoch_info(rpc: &DagRpcState) -> HandlerResult {
    let s = rpc.node.read().await;
    let blue_score = s.dag_store.max_blue_score();
    let current_epoch = compute_epoch(blue_score);

    Ok(json!({
        "currentEpoch": current_epoch,
        "currentBlueScore": blue_score,
        "blocksPerEpoch": misaka_dag::BLOCKS_PER_EPOCH,
    }))
}

// ═══════════════════════════════════════════════════════════════
//  Validators
// ═══════════════════════════════════════════════════════════════

/// `misaka_getValidatorSet` — list of known validators.
pub async fn get_validator_set(rpc: &DagRpcState) -> HandlerResult {
    let s = rpc.node.read().await;
    let validators: Vec<Value> = s
        .known_validators
        .iter()
        .map(|v| {
            json!({
                "validatorId": hex::encode(v.validator_id),
                "stakeWeight": v.stake_weight.to_string(),
                "publicKeyHex": hex::encode(&v.public_key.bytes),
                "isActive": v.is_active,
            })
        })
        .collect();

    Ok(json!({
        "validatorCount": s.validator_count,
        "validators": validators,
        "sr21Committee": crate::dag_rpc::dag_sr21_committee_json(&s),
    }))
}

/// `misaka_getValidatorById` — look up a validator by ID.
pub async fn get_validator_by_id(rpc: &DagRpcState, params: &Value) -> HandlerResult {
    let id_hex = params.get(0).and_then(|v| v.as_str()).ok_or_else(|| {
        (
            INVALID_PARAMS,
            "params[0]: expected validator_id hex".into(),
            None,
        )
    })?;

    let id_bytes: [u8; 32] = hex::decode(id_hex)
        .map_err(|e| (INVALID_PARAMS, format!("invalid hex: {}", e), None))?
        .try_into()
        .map_err(|_| (INVALID_PARAMS, "validator_id must be 32 bytes".into(), None))?;

    let s = rpc.node.read().await;
    let validator = s
        .known_validators
        .iter()
        .find(|v| v.validator_id == id_bytes);

    match validator {
        Some(v) => Ok(json!({
            "validatorId": hex::encode(v.validator_id),
            "stakeWeight": v.stake_weight.to_string(),
            "publicKeyHex": hex::encode(&v.public_key.bytes),
            "publicKeyBytes": v.public_key.bytes.len(),
            "isActive": v.is_active,
        })),
        None => Err((
            BLOCK_NOT_FOUND,
            format!("validator {} not found", id_hex),
            None,
        )),
    }
}

/// `misaka_getStakingInfo` — staking details (not implemented in v1.0).
pub async fn get_staking_info(_rpc: &DagRpcState, _params: &Value) -> HandlerResult {
    not_implemented("staking_info_not_available_in_v1.0")
}

// ═══════════════════════════════════════════════════════════════
//  Anonymity Set
// ═══════════════════════════════════════════════════════════════

/// `misaka_getAnonymitySet` — build ZKP anonymity set from UTXO spending pubkeys.
pub async fn get_anonymity_set(rpc: &DagRpcState, params: &Value) -> HandlerResult {
    use sha3::{Digest, Sha3_256};

    let tx_hash_hex = params.get(0).and_then(|v| v.as_str()).unwrap_or("");
    let output_index = params.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let set_size = params
        .get(2)
        .and_then(|v| v.as_u64())
        .unwrap_or(16)
        .max(4)
        .min(1024) as usize;

    let mut signer_tx_hash = [0u8; 32];
    if let Ok(decoded) = hex::decode(tx_hash_hex) {
        let len = decoded.len().min(32);
        signer_tx_hash[..len].copy_from_slice(&decoded[..len]);
    }

    let s = rpc.node.read().await;
    let all_keys = s.utxo_set.all_spending_keys();

    if all_keys.len() < set_size {
        return Err((
            INTERNAL_ERROR,
            format!(
                "insufficient UTXOs for anonymity set: need {}, have {}",
                set_size,
                all_keys.len()
            ),
            None,
        ));
    }

    // Hash each spending pubkey to create leaf hashes
    let mut all_leaf_hashes: Vec<[u8; 32]> = all_keys
        .values()
        .map(|pk_bytes| {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA_ANON_LEAF:");
            h.update(pk_bytes);
            h.finalize().into()
        })
        .collect();
    all_leaf_hashes.sort();

    // Find signer's leaf
    let signer_outref = misaka_types::utxo::OutputRef {
        tx_hash: signer_tx_hash,
        output_index,
    };
    let signer_leaf: Option<[u8; 32]> = all_keys.get(&signer_outref).map(|pk| {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_ANON_LEAF:");
        h.update(pk);
        h.finalize().into()
    });

    // Select set_size leaves, ensuring signer is included
    let mut selected: Vec<[u8; 32]> = Vec::with_capacity(set_size);
    let mut signer_index = 0usize;

    if let Some(s_leaf) = signer_leaf {
        selected.push(s_leaf);
        for leaf in &all_leaf_hashes {
            if selected.len() >= set_size {
                break;
            }
            if *leaf != s_leaf {
                selected.push(*leaf);
            }
        }
        // Sort and find signer index
        selected.sort();
        signer_index = selected.iter().position(|l| *l == s_leaf).unwrap_or(0);
    } else {
        selected.extend_from_slice(&all_leaf_hashes[..set_size.min(all_leaf_hashes.len())]);
    }

    Ok(json!({
        "leaves": selected.iter().map(hex::encode).collect::<Vec<_>>(),
        "signerIndex": signer_index,
        "setSize": selected.len(),
    }))
}

// ═══════════════════════════════════════════════════════════════
//  Range queries
// ═══════════════════════════════════════════════════════════════

/// `misaka_getBlocksRange` — iterate blocks by blue score range.
pub async fn get_blocks_range(rpc: &DagRpcState, params: &Value) -> HandlerResult {
    let from_score = params.get(0).and_then(|v| v.as_u64()).ok_or_else(|| {
        (
            INVALID_PARAMS,
            "params[0]: expected from_score (u64)".into(),
            None,
        )
    })?;
    let to_score = params.get(1).and_then(|v| v.as_u64()).ok_or_else(|| {
        (
            INVALID_PARAMS,
            "params[1]: expected to_score (u64)".into(),
            None,
        )
    })?;

    if to_score < from_score || (to_score - from_score) > 1000 {
        return Err((INVALID_PARAMS, "range must be <= 1000 blocks".into(), None));
    }

    let s = rpc.node.read().await;
    let snapshot = s.dag_store.snapshot();
    let tips = snapshot.get_tips();

    // Walk backwards from tips, collecting blocks in the score range.
    // This is a simplified approach; a production implementation would
    // use a score→hash index.
    let mut blocks = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut queue: Vec<[u8; 32]> = tips;

    while let Some(hash) = queue.pop() {
        if !visited.insert(hash) {
            continue;
        }
        if let Some(data) = snapshot.get_ghostdag_data(&hash) {
            if data.blue_score >= from_score && data.blue_score <= to_score {
                if let Some(header) = snapshot.get_header(&hash) {
                    blocks.push(json!({
                        "hash": hex::encode(hash),
                        "blueScore": data.blue_score,
                        "timestampMs": header.timestamp_ms,
                        "proposerId": hex::encode(header.proposer_id),
                    }));
                }
            }
            // Continue walking if we haven't reached the start of the range
            if data.blue_score > from_score && data.selected_parent != ZERO_HASH_BYTES {
                queue.push(data.selected_parent);
                for blue in &data.mergeset_blues {
                    queue.push(*blue);
                }
            }
        }
    }

    blocks.sort_by_key(|b| b["blueScore"].as_u64().unwrap_or(0));
    Ok(Value::Array(blocks))
}

/// `misaka_getTxsRange` — iterate transactions in a blue score range.
pub async fn get_txs_range(rpc: &DagRpcState, params: &Value) -> HandlerResult {
    let from_score = params.get(0).and_then(|v| v.as_u64()).ok_or_else(|| {
        (
            INVALID_PARAMS,
            "params[0]: expected from_score (u64)".into(),
            None,
        )
    })?;
    let to_score = params.get(1).and_then(|v| v.as_u64()).ok_or_else(|| {
        (
            INVALID_PARAMS,
            "params[1]: expected to_score (u64)".into(),
            None,
        )
    })?;

    if to_score < from_score || (to_score - from_score) > 1000 {
        return Err((INVALID_PARAMS, "range must be <= 1000 blocks".into(), None));
    }

    let s = rpc.node.read().await;
    let snapshot = s.dag_store.snapshot();
    let tips = snapshot.get_tips();

    let mut txs = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut queue: Vec<[u8; 32]> = tips;

    while let Some(hash) = queue.pop() {
        if !visited.insert(hash) {
            continue;
        }
        if let Some(data) = snapshot.get_ghostdag_data(&hash) {
            if data.blue_score >= from_score && data.blue_score <= to_score {
                for tx in s.dag_store.get_block_txs(&hash) {
                    txs.push(json!({
                        "txHash": hex::encode(tx.tx_hash()),
                        "blockHash": hex::encode(hash),
                        "blueScore": data.blue_score,
                        "txType": format!("{:?}", tx.tx_type),
                        "fee": tx.fee,
                    }));
                }
            }
            if data.blue_score > from_score && data.selected_parent != ZERO_HASH_BYTES {
                queue.push(data.selected_parent);
                for blue in &data.mergeset_blues {
                    queue.push(*blue);
                }
            }
        }
    }

    Ok(Value::Array(txs))
}

// ═══════════════════════════════════════════════════════════════
//  Utilities
// ═══════════════════════════════════════════════════════════════

/// Return a NOT_IMPLEMENTED error with a descriptive reason.
pub fn not_implemented(reason: &str) -> HandlerResult {
    Err((
        NOT_IMPLEMENTED,
        format!("not implemented: {}", reason),
        None,
    ))
}
