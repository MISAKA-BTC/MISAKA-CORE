#[cfg(any(
    feature = "shielded-groth16-verifier",
    feature = "shielded-plonk-verifier"
))]
use std::sync::Arc;

use crate::shielded_hook_impl::ShieldedVerifierAdapters;

#[cfg(feature = "shielded-groth16-verifier")]
use ark_bls12_381::{Bls12_381, Fr};
#[cfg(feature = "shielded-groth16-verifier")]
use ark_ff::PrimeField;
#[cfg(feature = "shielded-groth16-verifier")]
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
#[cfg(feature = "shielded-groth16-verifier")]
use ark_serialize::CanonicalDeserialize;
#[cfg(feature = "shielded-groth16-verifier")]
use ark_snark::SNARK;
#[cfg(feature = "shielded-plonk-verifier")]
use dusk_bytes::DeserializableSlice;
#[cfg(feature = "shielded-plonk-verifier")]
use dusk_plonk::prelude::{
    BlsScalar, Error as DuskPlonkError, Proof as DuskPlonkProof, Verifier as DuskPlonkVerifier,
};
#[cfg(feature = "shielded-groth16-verifier")]
use misaka_shielded::{Groth16VerifierAdapter, ParsedGroth16ProofPayload};
#[cfg(feature = "shielded-plonk-verifier")]
use misaka_shielded::{ParsedPlonkProofPayload, PlonkVerifierAdapter};
#[cfg(any(
    feature = "shielded-groth16-verifier",
    feature = "shielded-plonk-verifier"
))]
use misaka_shielded::{ProofError, ShieldedPublicInputs};

#[cfg(feature = "shielded-groth16-verifier")]
#[derive(Debug, Default)]
pub struct ArkGroth16VerifierAdapter;

#[cfg(feature = "shielded-groth16-verifier")]
impl Groth16VerifierAdapter for ArkGroth16VerifierAdapter {
    fn verify(
        &self,
        verifying_key_bytes: &[u8],
        _public_inputs: &ShieldedPublicInputs,
        _canonical_public_inputs: &[u8],
        canonical_public_input_words: &[[u8; 32]],
        payload: &ParsedGroth16ProofPayload,
    ) -> Result<(), ProofError> {
        let verifying_key =
            VerifyingKey::<Bls12_381>::deserialize_compressed(&mut &verifying_key_bytes[..])
                .map_err(|e| ProofError::Malformed(format!("Groth16 VK deserialize: {e}")))?;
        let proof = Proof::<Bls12_381>::deserialize_compressed(&mut &payload.proof_bytes[..])
            .map_err(|e| ProofError::Malformed(format!("Groth16 proof deserialize: {e}")))?;
        let public_inputs = canonical_public_input_words
            .iter()
            .map(|word| Fr::from_le_bytes_mod_order(word))
            .collect::<Vec<_>>();
        let prepared = prepare_verifying_key(&verifying_key);
        let verified =
            Groth16::<Bls12_381>::verify_with_processed_vk(&prepared, &public_inputs, &proof)
                .map_err(|e| ProofError::Malformed(format!("Groth16 verify error: {e}")))?;
        if verified {
            Ok(())
        } else {
            Err(ProofError::VerificationFailed)
        }
    }
}

#[cfg(feature = "shielded-plonk-verifier")]
#[derive(Debug, Default)]
pub struct DuskPlonkVerifierAdapter;

#[cfg(feature = "shielded-plonk-verifier")]
fn plonk_scalar_from_word(word: &[u8; 32]) -> BlsScalar {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(word);
    BlsScalar::from_bytes_wide(&wide)
}

#[cfg(feature = "shielded-plonk-verifier")]
fn map_plonk_error(err: DuskPlonkError) -> ProofError {
    match err {
        DuskPlonkError::ProofVerificationError | DuskPlonkError::PairingCheckFailure => {
            ProofError::VerificationFailed
        }
        DuskPlonkError::InvalidPublicInputBytes
        | DuskPlonkError::PublicInputNotFound { .. }
        | DuskPlonkError::InconsistentPublicInputsLen { .. } => {
            ProofError::InvalidPublicInputs(err.to_string())
        }
        _ => ProofError::Malformed(format!("PLONK verify error: {err}")),
    }
}

#[cfg(feature = "shielded-plonk-verifier")]
impl PlonkVerifierAdapter for DuskPlonkVerifierAdapter {
    fn verify(
        &self,
        verifying_key_bytes: &[u8],
        _public_inputs: &ShieldedPublicInputs,
        _canonical_public_inputs: &[u8],
        canonical_public_input_words: &[[u8; 32]],
        payload: &ParsedPlonkProofPayload,
    ) -> Result<(), ProofError> {
        let verifier = DuskPlonkVerifier::try_from_bytes(verifying_key_bytes)
            .map_err(|e| ProofError::Malformed(format!("PLONK verifier deserialize: {e}")))?;
        let proof = DuskPlonkProof::from_slice(&payload.proof_bytes)
            .map_err(|e| ProofError::Malformed(format!("PLONK proof deserialize: {e:?}")))?;
        let public_inputs = canonical_public_input_words
            .iter()
            .map(plonk_scalar_from_word)
            .collect::<Vec<_>>();
        verifier
            .verify(&proof, &public_inputs)
            .map_err(map_plonk_error)
    }
}

pub fn compiled_startup_verifier_adapters() -> ShieldedVerifierAdapters {
    ShieldedVerifierAdapters {
        #[cfg(feature = "shielded-groth16-verifier")]
        groth16: Some(Arc::new(ArkGroth16VerifierAdapter)),
        #[cfg(not(feature = "shielded-groth16-verifier"))]
        groth16: None,
        #[cfg(feature = "shielded-plonk-verifier")]
        plonk: Some(Arc::new(DuskPlonkVerifierAdapter)),
        #[cfg(not(feature = "shielded-plonk-verifier"))]
        plonk: None,
    }
}

#[cfg(all(
    test,
    any(
        feature = "shielded-groth16-verifier",
        feature = "shielded-plonk-verifier"
    )
))]
#[allow(dead_code, clippy::expect_used, clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;
    #[cfg(any(feature = "shielded-groth16-verifier", feature = "shielded-plonk-verifier"))]
    use misaka_shielded::ProofBackend;
    #[cfg(feature = "shielded-groth16-verifier")]
    use misaka_shielded::Groth16Backend;
    #[cfg(feature = "shielded-plonk-verifier")]
    use misaka_shielded::PlonkBackend;
    use serde_json::json;
    use std::sync::Arc;
    use std::time::Instant;
    #[cfg(feature = "shielded-groth16-verifier")]
    use ark_bls12_381::Fr;
    #[cfg(feature = "shielded-groth16-verifier")]
    use ark_ff::PrimeField;
    #[cfg(feature = "shielded-groth16-verifier")]
    use ark_groth16::Groth16;
    #[cfg(feature = "shielded-groth16-verifier")]
    use ark_relations::lc;
    #[cfg(feature = "shielded-groth16-verifier")]
    use ark_relations::r1cs::{
        ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable,
    };
    #[cfg(feature = "shielded-groth16-verifier")]
    use ark_serialize::CanonicalSerialize;
    #[cfg(feature = "shielded-groth16-verifier")]
    use ark_snark::SNARK;
    #[cfg(feature = "shielded-groth16-verifier")]
    use ark_std::rand::{rngs::StdRng as Groth16StdRng, SeedableRng as Groth16SeedableRng};
    #[cfg(feature = "shielded-plonk-verifier")]
    use dusk_bytes::Serializable;
    #[cfg(feature = "shielded-plonk-verifier")]
    use dusk_plonk::prelude::{
        Circuit as DuskPlonkCircuit, Compiler as DuskPlonkCompiler, Composer as DuskPlonkComposer,
        Error as DuskPlonkError, PublicParameters as DuskPlonkPublicParameters,
    };
    use misaka_shielded::{
        CircuitVersion, NoteCommitment, Nullifier, ShieldedProof, ShieldedPublicInputs, TreeRoot,
    };
    #[cfg(feature = "shielded-plonk-verifier")]
    use rand::rngs::StdRng as PlonkStdRng;

    const SHELL_PROOF_ENVELOPE_SCHEMA_V1: u8 = 1;
    #[cfg(feature = "shielded-groth16-verifier")]
    const GROTH16_TEST_SETUP_SEED: u64 = 0x4752_4f54_4831_3656;
    #[cfg(feature = "shielded-plonk-verifier")]
    const PLONK_TEST_SETUP_SEED: u64 = 0x504c_4f4e_4b31_5652;

    fn dummy_inputs_for_version(circuit_version: CircuitVersion) -> ShieldedPublicInputs {
        ShieldedPublicInputs {
            anchor: TreeRoot::empty(),
            nullifiers: vec![Nullifier([0x11; 32])],
            output_commitments: vec![NoteCommitment([0x22; 32])],
            fee: 100,
            withdraw_amount: None,
            circuit_version,
        }
    }

    fn build_vk_artifact(
        backend_tag: u8,
        circuit_version: CircuitVersion,
        verifying_key_bytes: &[u8],
    ) -> Vec<u8> {
        let mut artifact = Vec::new();
        artifact.extend_from_slice(b"MSVK");
        artifact.push(1);
        artifact.push(backend_tag);
        artifact.extend_from_slice(&circuit_version.0.to_le_bytes());
        artifact.push(1);
        artifact.extend_from_slice(&(verifying_key_bytes.len() as u32).to_le_bytes());
        artifact.extend_from_slice(verifying_key_bytes);
        artifact
    }

    fn build_shell_proof_envelope(
        kind_tag: u8,
        verifying_key_bytes: &[u8],
        canonical_inputs: &[u8],
        proof_bytes: &[u8],
    ) -> ShieldedProof {
        let vk_fingerprint = {
            let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded vk fingerprint v1");
            hasher.update(verifying_key_bytes);
            *hasher.finalize().as_bytes()
        };
        let public_input_hash = {
            let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded public input hash v1");
            hasher.update(canonical_inputs);
            *hasher.finalize().as_bytes()
        };
        let mut bytes = Vec::with_capacity(4 + 1 + 1 + 32 + 32 + proof_bytes.len());
        bytes.extend_from_slice(b"MSKP");
        bytes.push(SHELL_PROOF_ENVELOPE_SCHEMA_V1);
        bytes.push(kind_tag);
        bytes.extend_from_slice(&vk_fingerprint);
        bytes.extend_from_slice(&public_input_hash);
        bytes.extend_from_slice(proof_bytes);
        ShieldedProof { bytes }
    }

    #[cfg(feature = "shielded-groth16-verifier")]
    #[derive(Clone)]
    struct EchoPublicInputsGroth16Circuit {
        public_inputs: Vec<Fr>,
    }

    #[cfg(feature = "shielded-groth16-verifier")]
    impl ConstraintSynthesizer<Fr> for EchoPublicInputsGroth16Circuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let allocated = self
                .public_inputs
                .into_iter()
                .map(|value| cs.new_input_variable(|| Ok(value)))
                .collect::<Result<Vec<_>, _>>()?;
            let first = allocated.first().copied().unwrap_or(Variable::One);
            cs.enforce_constraint(lc!() + Variable::One, lc!() + first, lc!() + first)?;
            Ok(())
        }
    }

    #[cfg(feature = "shielded-groth16-verifier")]
    fn sample_groth16_vk_and_payload(
        inputs: &ShieldedPublicInputs,
    ) -> (Vec<u8>, ParsedGroth16ProofPayload, Vec<[u8; 32]>) {
        let canonical_words = inputs.canonical_word_chunks_v1().expect("canonical words");
        let field_inputs = canonical_words
            .iter()
            .map(|word| Fr::from_le_bytes_mod_order(word))
            .collect::<Vec<_>>();
        let circuit = EchoPublicInputsGroth16Circuit {
            public_inputs: field_inputs,
        };
        let mut rng = Groth16StdRng::seed_from_u64(GROTH16_TEST_SETUP_SEED);
        let (pk, vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng).expect("setup");
        let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).expect("proof");

        let mut vk_bytes = Vec::new();
        vk.serialize_compressed(&mut vk_bytes)
            .expect("serialize vk");
        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .expect("serialize proof");
        (
            vk_bytes,
            ParsedGroth16ProofPayload { proof_bytes },
            canonical_words,
        )
    }

    #[cfg(feature = "shielded-groth16-verifier")]
    pub(crate) fn sample_groth16_vk_bytes() -> Vec<u8> {
        let inputs = dummy_inputs_for_version(CircuitVersion::GROTH16_V1);
        let (vk_bytes, _, _) = sample_groth16_vk_and_payload(&inputs);
        vk_bytes
    }

    #[cfg(feature = "shielded-groth16-verifier")]
    pub(crate) fn sample_groth16_vk_and_shell_proof_for_inputs(
        inputs: &ShieldedPublicInputs,
    ) -> (Vec<u8>, ShieldedProof) {
        let (vk_bytes, payload, _) = sample_groth16_vk_and_payload(inputs);
        let canonical_inputs = inputs.canonical_bytes_v1().expect("canonical inputs");
        (
            vk_bytes.clone(),
            build_shell_proof_envelope(1, &vk_bytes, &canonical_inputs, &payload.proof_bytes),
        )
    }

    #[cfg(feature = "shielded-groth16-verifier")]
    pub(crate) fn sample_groth16_vk_artifact_bytes_for_inputs(
        inputs: &ShieldedPublicInputs,
    ) -> Vec<u8> {
        let (vk_bytes, _) = sample_groth16_vk_and_shell_proof_for_inputs(inputs);
        build_vk_artifact(1, CircuitVersion::GROTH16_V1, &vk_bytes)
    }

    #[cfg(feature = "shielded-plonk-verifier")]
    #[derive(Clone, Default)]
    struct EchoPublicInputsPlonkCircuit {
        public_inputs: Vec<BlsScalar>,
    }

    #[cfg(feature = "shielded-plonk-verifier")]
    impl DuskPlonkCircuit for EchoPublicInputsPlonkCircuit {
        fn circuit(&self, composer: &mut DuskPlonkComposer) -> Result<(), DuskPlonkError> {
            for value in &self.public_inputs {
                composer.append_public(*value);
            }
            Ok(())
        }
    }

    #[cfg(feature = "shielded-plonk-verifier")]
    fn sample_plonk_verifier_and_payload(
        inputs: &ShieldedPublicInputs,
    ) -> (Vec<u8>, ParsedPlonkProofPayload, Vec<[u8; 32]>) {
        let canonical_words = inputs.canonical_word_chunks_v1().expect("canonical words");
        let public_inputs = canonical_words
            .iter()
            .map(plonk_scalar_from_word)
            .collect::<Vec<_>>();
        let circuit = EchoPublicInputsPlonkCircuit {
            public_inputs: public_inputs.clone(),
        };
        let mut rng =
            <PlonkStdRng as rand::SeedableRng>::seed_from_u64(PLONK_TEST_SETUP_SEED);
        let pp = DuskPlonkPublicParameters::setup(1 << 11, &mut rng).expect("pp");
        let (prover, verifier) =
            DuskPlonkCompiler::compile_with_circuit(&pp, b"misaka-plonk-adapter", &circuit)
                .expect("compile");
        let (proof, proof_inputs) = prover.prove(&mut rng, &circuit).expect("prove");
        assert_eq!(proof_inputs, public_inputs);
        (
            verifier.to_bytes(),
            ParsedPlonkProofPayload {
                proof_bytes: proof.to_bytes().to_vec(),
            },
            canonical_words,
        )
    }

    #[cfg(feature = "shielded-plonk-verifier")]
    pub(crate) fn sample_plonk_vk_bytes() -> Vec<u8> {
        let inputs = dummy_inputs_for_version(CircuitVersion::PLONK_V1);
        let (vk_bytes, _, _) = sample_plonk_verifier_and_payload(&inputs);
        vk_bytes
    }

    #[cfg(feature = "shielded-plonk-verifier")]
    pub(crate) fn sample_plonk_vk_and_shell_proof_for_inputs(
        inputs: &ShieldedPublicInputs,
    ) -> (Vec<u8>, ShieldedProof) {
        let (vk_bytes, payload, _) = sample_plonk_verifier_and_payload(inputs);
        let canonical_inputs = inputs.canonical_bytes_v1().expect("canonical inputs");
        (
            vk_bytes.clone(),
            build_shell_proof_envelope(2, &vk_bytes, &canonical_inputs, &payload.proof_bytes),
        )
    }

    #[cfg(feature = "shielded-plonk-verifier")]
    pub(crate) fn sample_plonk_vk_artifact_bytes_for_inputs(
        inputs: &ShieldedPublicInputs,
    ) -> Vec<u8> {
        let (vk_bytes, _) = sample_plonk_vk_and_shell_proof_for_inputs(inputs);
        build_vk_artifact(2, CircuitVersion::PLONK_V1, &vk_bytes)
    }

    #[cfg(feature = "shielded-groth16-verifier")]
    fn benchmark_groth16_compiled_backend() -> serde_json::Value {
        let inputs = dummy_inputs_for_version(CircuitVersion::GROTH16_V1);
        let canonical_inputs = inputs.canonical_bytes_v1().expect("canonical inputs");

        let build_start = Instant::now();
        let (vk_bytes, payload, _) = sample_groth16_vk_and_payload(&inputs);
        let proof = build_shell_proof_envelope(1, &vk_bytes, &canonical_inputs, &payload.proof_bytes);
        let build_micros = build_start.elapsed().as_micros();

        let backend = Groth16Backend::new(CircuitVersion::GROTH16_V1, vk_bytes.clone())
            .with_verifier_adapter(Arc::new(ArkGroth16VerifierAdapter));
        let limit = backend.proof_size_limit();

        let verify_start = Instant::now();
        backend.verify(&inputs, &proof).expect("must verify");
        let verify_micros = verify_start.elapsed().as_micros();

        json!({
            "backendId": "groth16-v1",
            "circuitVersion": CircuitVersion::GROTH16_V1.0,
            "proofBytes": proof.bytes.len(),
            "proofPayloadBytes": payload.proof_bytes.len(),
            "proofSizeLimit": limit,
            "proofHeadroomBytes": limit.saturating_sub(proof.bytes.len()),
            "verifyingKeyBytes": vk_bytes.len(),
            "buildMicros": build_micros,
            "verifyMicros": verify_micros,
            "verificationPassed": true,
            "nullifierCount": inputs.nullifiers.len(),
            "outputCommitmentCount": inputs.output_commitments.len(),
            "canonicalWordCount": inputs.canonical_word_chunks_v1().expect("canonical words").len(),
            "anchor": hex::encode(inputs.anchor.0),
        })
    }

    #[cfg(feature = "shielded-plonk-verifier")]
    fn benchmark_plonk_compiled_backend() -> serde_json::Value {
        let inputs = dummy_inputs_for_version(CircuitVersion::PLONK_V1);
        let canonical_inputs = inputs.canonical_bytes_v1().expect("canonical inputs");

        let build_start = Instant::now();
        let (vk_bytes, payload, _) = sample_plonk_verifier_and_payload(&inputs);
        let proof = build_shell_proof_envelope(2, &vk_bytes, &canonical_inputs, &payload.proof_bytes);
        let build_micros = build_start.elapsed().as_micros();

        let backend = PlonkBackend::new(CircuitVersion::PLONK_V1, vk_bytes.clone())
            .with_verifier_adapter(Arc::new(DuskPlonkVerifierAdapter));
        let limit = backend.proof_size_limit();

        let verify_start = Instant::now();
        backend.verify(&inputs, &proof).expect("must verify");
        let verify_micros = verify_start.elapsed().as_micros();

        json!({
            "backendId": "plonk-v1",
            "circuitVersion": CircuitVersion::PLONK_V1.0,
            "proofBytes": proof.bytes.len(),
            "proofPayloadBytes": payload.proof_bytes.len(),
            "proofSizeLimit": limit,
            "proofHeadroomBytes": limit.saturating_sub(proof.bytes.len()),
            "verifyingKeyBytes": vk_bytes.len(),
            "buildMicros": build_micros,
            "verifyMicros": verify_micros,
            "verificationPassed": true,
            "nullifierCount": inputs.nullifiers.len(),
            "outputCommitmentCount": inputs.output_commitments.len(),
            "canonicalWordCount": inputs.canonical_word_chunks_v1().expect("canonical words").len(),
            "anchor": hex::encode(inputs.anchor.0),
        })
    }

    #[cfg(all(feature = "shielded-groth16-verifier", feature = "shielded-plonk-verifier"))]
    #[test]
    fn compiled_verifier_benchmark_emits_current_groth16_plonk_baselines() {
        let payload = json!({
            "status": "ok",
            "benchmarks": [
                benchmark_groth16_compiled_backend(),
                benchmark_plonk_compiled_backend(),
            ]
        });

        if let Ok(path) = std::env::var("MISAKA_SHIELDED_COMPARATIVE_BENCHMARK_RESULT") {
            std::fs::write(&path, serde_json::to_string_pretty(&payload).expect("json"))
                .expect("write benchmark result");
        }

        println!("{}", serde_json::to_string(&payload).expect("json"));
    }

    #[cfg(feature = "shielded-groth16-verifier")]
    #[test]
    fn ark_groth16_adapter_verifies_valid_proof() {
        let adapter = ArkGroth16VerifierAdapter;
        let inputs = dummy_inputs_for_version(CircuitVersion::GROTH16_V1);
        let canonical_bytes = inputs.canonical_bytes_v1().expect("canonical bytes");
        let (vk_bytes, payload, canonical_words) = sample_groth16_vk_and_payload(&inputs);
        adapter
            .verify(
                &vk_bytes,
                &inputs,
                &canonical_bytes,
                &canonical_words,
                &payload,
            )
            .expect("must verify");
    }

    #[cfg(feature = "shielded-groth16-verifier")]
    #[test]
    fn ark_groth16_adapter_rejects_modified_public_inputs() {
        let adapter = ArkGroth16VerifierAdapter;
        let inputs = dummy_inputs_for_version(CircuitVersion::GROTH16_V1);
        let canonical_bytes = inputs.canonical_bytes_v1().expect("canonical bytes");
        let (vk_bytes, payload, mut canonical_words) = sample_groth16_vk_and_payload(&inputs);
        canonical_words[0][0] ^= 0x01;
        let err = adapter
            .verify(
                &vk_bytes,
                &inputs,
                &canonical_bytes,
                &canonical_words,
                &payload,
            )
            .expect_err("must reject");
        assert!(matches!(err, ProofError::VerificationFailed));
    }

    #[cfg(feature = "shielded-plonk-verifier")]
    #[test]
    fn dusk_plonk_adapter_verifies_valid_proof() {
        let adapter = DuskPlonkVerifierAdapter;
        let inputs = dummy_inputs_for_version(CircuitVersion::PLONK_V1);
        let canonical_bytes = inputs.canonical_bytes_v1().expect("canonical bytes");
        let (vk_bytes, payload, canonical_words) = sample_plonk_verifier_and_payload(&inputs);
        adapter
            .verify(
                &vk_bytes,
                &inputs,
                &canonical_bytes,
                &canonical_words,
                &payload,
            )
            .expect("must verify");
    }

    #[cfg(feature = "shielded-plonk-verifier")]
    #[test]
    fn dusk_plonk_adapter_rejects_modified_public_inputs() {
        let adapter = DuskPlonkVerifierAdapter;
        let inputs = dummy_inputs_for_version(CircuitVersion::PLONK_V1);
        let canonical_bytes = inputs.canonical_bytes_v1().expect("canonical bytes");
        let (vk_bytes, payload, mut canonical_words) = sample_plonk_verifier_and_payload(&inputs);
        canonical_words[0][0] ^= 0x01;
        let err = adapter
            .verify(
                &vk_bytes,
                &inputs,
                &canonical_bytes,
                &canonical_words,
                &payload,
            )
            .expect_err("must reject");
        assert!(matches!(err, ProofError::VerificationFailed));
    }

    #[test]
    fn compiled_startup_verifier_adapters_exports_enabled_verifiers() {
        let adapters = compiled_startup_verifier_adapters();
        #[cfg(feature = "shielded-groth16-verifier")]
        assert!(adapters.groth16.is_some());
        #[cfg(not(feature = "shielded-groth16-verifier"))]
        assert!(adapters.groth16.is_none());
        #[cfg(feature = "shielded-plonk-verifier")]
        assert!(adapters.plonk.is_some());
        #[cfg(not(feature = "shielded-plonk-verifier"))]
        assert!(adapters.plonk.is_none());
    }
}
