use misaka_shielded::proof_backend::compiled_backend_catalog;
use misaka_shielded::sha3_proof::{ProofInput, ProofOutput};
use misaka_shielded::{
    CircuitVersion, ProofBackend, Sha3TransferProofBackend, Sha3TransferProofBuilder,
    ShieldedProof, ShieldedPublicInputs, TreeRoot,
};
use serde_json::json;
use std::time::Instant;

fn current_sha3_sample() -> (ShieldedPublicInputs, ShieldedProof, usize, usize, u128) {
    let value_in = 1_000u64;
    let asset_id = 0u64;
    let fee = 100u64;
    let value_out = 900u64;
    let rcm_in = [42u8; 32];
    let nk_commit = [7u8; 32];
    let cm_in =
        Sha3TransferProofBackend::compute_commitment(value_in, asset_id, &nk_commit, &rcm_in);

    let empty_sibling = blake3::derive_key("MISAKA shielded empty leaf v1", &[]);
    let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded node v1");
    hasher.update(&cm_in);
    hasher.update(&empty_sibling);
    let root: [u8; 32] = *hasher.finalize().as_bytes();

    let rcm_out = [99u8; 32];
    let recipient = [55u8; 32];

    let mut builder = Sha3TransferProofBuilder::new(fee);
    builder.add_input(ProofInput {
        position: 0,
        merkle_siblings: vec![empty_sibling],
        value: value_in,
        asset_id,
        rcm: rcm_in,
        nk_commit,
    });
    builder.add_output(ProofOutput {
        value: value_out,
        asset_id,
        recipient_pk: recipient,
        rcm: rcm_out,
    });

    let build_start = Instant::now();
    let (proof, nullifiers, commitments) = builder.build().expect("proof build must succeed");
    let build_elapsed = build_start.elapsed();

    (
        ShieldedPublicInputs {
            anchor: TreeRoot(root),
            nullifiers,
            output_commitments: commitments,
            fee,
            withdraw_amount: None,
            circuit_version: CircuitVersion::SHA3_TRANSFER_V2,
        },
        proof,
        1,
        1,
        build_elapsed.as_micros(),
    )
}

#[test]
fn layer4_benchmark_emits_current_sha3_baseline() {
    let backend = Sha3TransferProofBackend::new();
    let (public_inputs, proof, input_count, output_count, build_micros) = current_sha3_sample();
    let limit = backend.proof_size_limit();

    let verify_start = Instant::now();
    backend
        .verify(&public_inputs, &proof)
        .expect("sha3 proof must verify");
    let verify_elapsed = verify_start.elapsed();

    assert!(proof.bytes.len() <= limit);

    let catalog = compiled_backend_catalog()
        .into_iter()
        .map(|status| {
            json!({
                "backendId": status.descriptor.backend_id,
                "backendKind": format!("{:?}", status.descriptor.backend_kind),
                "phase": format!("{:?}", status.descriptor.phase),
                "productionReady": status.descriptor.production_ready,
                "transferCapable": status.descriptor.transfer_capable,
                "verifierBodyImplemented": status.verifier_body_implemented,
                "verifyingKeyRequired": status.verifying_key_required,
                "verifyingKeyLoaded": status.verifying_key_loaded,
                "proofSizeLimit": status.descriptor.proof_size_limit
            })
        })
        .collect::<Vec<_>>();

    let payload = json!({
        "status": "ok",
        "benchmark": {
            "backendId": "sha3-transfer-v2",
            "circuitVersion": CircuitVersion::SHA3_TRANSFER_V2.0,
            "inputCount": input_count,
            "outputCount": output_count,
            "proofBytes": proof.bytes.len(),
            "proofSizeLimit": limit,
            "proofHeadroomBytes": limit.saturating_sub(proof.bytes.len()),
            "buildMicros": build_micros,
            "verifyMicros": verify_elapsed.as_micros(),
            "nullifierCount": public_inputs.nullifiers.len(),
            "outputCommitmentCount": public_inputs.output_commitments.len(),
            "anchor": hex::encode(public_inputs.anchor.0),
            "verificationPassed": true
        },
        "compiledCatalog": catalog
    });

    if let Ok(path) = std::env::var("MISAKA_SHIELDED_BENCHMARK_RESULT") {
        std::fs::write(&path, serde_json::to_string_pretty(&payload).expect("json"))
            .expect("write benchmark result");
    }

    println!("{}", serde_json::to_string(&payload).expect("json"));
}
