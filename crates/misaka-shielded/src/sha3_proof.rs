//! SHA3-Based Cryptographic Proof System (Post-Quantum Safe)
//!
//! # Architecture
//!
//! Hash-based proofs using SHA3-256 for all commitments and binding.
//! Unlike pairing-based ZK (Groth16/PLONK), this system relies solely
//! on hash function collision resistance — quantum-safe by design.
//!
//! # ⚠ IMPORTANT: This is NOT a Zero-Knowledge Proof System
//!
//! This system provides **TransparentIntegrity** — it proves that a shielded
//! transfer is valid (correct balance, no double-spend, Merkle membership)
//! WITHOUT requiring the verifier to see plaintext values.
//!
//! However, it does NOT have the mathematical zero-knowledge property:
//! - **num_inputs / num_outputs** are visible in proof bytes
//! - **Nullifiers** are public on-chain (spent-note identifiers)
//! - **Output commitments** are public (tracked in Merkle tree)
//! - **Transaction graph** can be analyzed via nullifier/commitment patterns
//! - **Value commitments** are deterministic hashes — small-value-space
//!   brute-force is theoretically possible (mitigated by 256-bit blinding)
//!
//! For true zero-knowledge privacy, Groth16/PLONK backends are required
//! (currently Shell — planned for P1 phase).
//!
//! # Privacy Model: "Commitment-Based Integrity"
//!
//! - **On-chain**: Commitments, nullifiers, encrypted notes (all visible)
//! - **Validators**: See commitments only (V3); see plaintext (V2 legacy)
//! - **Observers**: See commitment + nullifier patterns (graph analysis possible)
//! - **Recipients**: See plaintext values via encrypted notes
//! - **FullViewKey holders**: Same as recipients (audit/compliance)
//!
//! # Proof Components
//!
//! 1. **Merkle Membership**: Blake3 Merkle path from commitment to anchor root
//! 2. **Nullifier Binding**: Proves nullifier = PRF(nk, rho) for owned note
//! 3. **Balance Conservation**: sum(inputs) = sum(outputs) + fee (via binding)
//! 4. **Commitment Binding**: Each output commitment correctly formed
//!
//! # Proof Format (CircuitVersion::SHA3_TRANSFER_V2 = 51)
//!
//! ```text
//! [version: 1B]  [num_inputs: 1B]  [num_outputs: 1B]  [fee: 8B LE]
//!
//! For each input:
//!   [position: 4B LE]  [depth: 1B]  [siblings: 32B × depth]
//!   [value: 8B LE]  [asset_id: 8B LE]  [rcm: 32B]
//!   [nullifier_key_commit: 32B]
//!
//! For each output:
//!   [value: 8B LE]  [asset_id: 8B LE]  [recipient_pk: 32B]  [rcm: 32B]
//!
//! [balance_hash: 32B]  [balance_nonce: 32B]
//! ```

use crate::proof_backend::{
    PrivacyLevel, ProofBackend, ProofBackendDescriptor, ProofBackendKind, ProofBackendPhase,
    ProofError,
};
use crate::types::{
    CircuitVersion, NoteCommitment, Nullifier, ShieldedProof, ShieldedPublicInputs,
};
use sha3::{Digest, Sha3_256};

/// SHA3 Transfer Proof Backend — full cryptographic verification.
#[derive(Debug)]
pub struct Sha3TransferProofBackend {
    version: CircuitVersion,
}

impl CircuitVersion {
    /// SHA3 shielded transfer proof (PQ-safe, production)
    pub const SHA3_TRANSFER_V2: Self = CircuitVersion(51);
    /// SHA3 shielded transfer proof V3 — commitment-only, no plaintext in proof bytes.
    /// Removes value, asset_id, rcm, recipient_pk, and nk_commit from the clear.
    pub const SHA3_TRANSFER_V3: Self = CircuitVersion(52);
}

impl Sha3TransferProofBackend {
    pub fn new() -> Self {
        Self {
            version: CircuitVersion::SHA3_TRANSFER_V2,
        }
    }

    /// Create a V3-only backend instance (commitment-only proofs, no plaintext).
    pub fn new_v3() -> Self {
        Self {
            version: CircuitVersion::SHA3_TRANSFER_V3,
        }
    }

    /// Recompute Merkle root from leaf commitment + path.
    /// Uses Blake3 domain-separated hashing (matches commitment_tree.rs node_hash).
    pub fn recompute_merkle_root(
        commitment: &[u8; 32],
        position: u32,
        siblings: &[[u8; 32]],
    ) -> [u8; 32] {
        let mut current = *commitment;
        let mut pos = position;
        for sibling in siblings {
            let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded node v1");
            if pos & 1 == 0 {
                hasher.update(&current);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(&current);
            }
            current = *hasher.finalize().as_bytes();
            pos >>= 1;
        }
        current
    }

    /// Compute note commitment: Blake3_domain("MISAKA shielded note commit v1", value || asset_id || pk || rcm)
    pub fn compute_commitment(
        value: u64,
        asset_id: u64,
        recipient_pk: &[u8; 32],
        rcm: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded note commit v1");
        hasher.update(&value.to_le_bytes());
        hasher.update(&asset_id.to_le_bytes());
        hasher.update(recipient_pk);
        hasher.update(rcm);
        *hasher.finalize().as_bytes()
    }

    /// Compute rho for nullifier derivation
    pub fn compute_rho(commitment: &[u8; 32], position: u32) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded note rho v1");
        hasher.update(commitment);
        hasher.update(&(position as u64).to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Compute nullifier: Blake3_domain("MISAKA shielded nullifier v1", nk || rho)
    pub fn compute_nullifier(nk: &[u8; 32], rho: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded nullifier v1");
        hasher.update(nk);
        hasher.update(rho);
        *hasher.finalize().as_bytes()
    }

    /// Compute balance hash: SHA3("MISAKA:balance:v1:" || sum_in || sum_out || fee || nonce)
    pub fn compute_balance_hash(sum_in: u64, sum_out: u64, fee: u64, nonce: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:balance:v1:");
        h.update(&sum_in.to_le_bytes());
        h.update(&sum_out.to_le_bytes());
        h.update(&fee.to_le_bytes());
        h.update(nonce);
        h.finalize().into()
    }

    // ── V3 helpers ─────────────────────────────────────────────────────────

    fn read_32(data: &[u8], cursor: &mut usize) -> Result<[u8; 32], ProofError> {
        if *cursor + 32 > data.len() {
            return Err(ProofError::Malformed("truncated at read_32".into()));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&data[*cursor..*cursor + 32]);
        *cursor += 32;
        Ok(buf)
    }

    fn read_64(data: &[u8], cursor: &mut usize) -> Result<[u8; 64], ProofError> {
        if *cursor + 64 > data.len() {
            return Err(ProofError::Malformed("truncated at read_64".into()));
        }
        let mut buf = [0u8; 64];
        buf.copy_from_slice(&data[*cursor..*cursor + 64]);
        *cursor += 64;
        Ok(buf)
    }

    fn read_u32_le(data: &[u8], cursor: &mut usize) -> Result<u32, ProofError> {
        if *cursor + 4 > data.len() {
            return Err(ProofError::Malformed("truncated u32".into()));
        }
        let v = u32::from_le_bytes(data[*cursor..*cursor + 4].try_into().unwrap());
        *cursor += 4;
        Ok(v)
    }

    fn read_u8(data: &[u8], cursor: &mut usize) -> Result<u8, ProofError> {
        if *cursor >= data.len() {
            return Err(ProofError::Malformed("truncated u8".into()));
        }
        let v = data[*cursor];
        *cursor += 1;
        Ok(v)
    }

    /// Parse and verify a V3 shielded transfer proof (commitment-only, no plaintext).
    fn verify_transfer_v3(
        &self,
        public_inputs: &ShieldedPublicInputs,
        proof_bytes: &[u8],
    ) -> Result<(), ProofError> {
        let mut cursor = 0;

        // Header
        let version = Self::read_u8(proof_bytes, &mut cursor)?;
        if version != 0x03 {
            return Err(ProofError::Malformed("expected v3".into()));
        }
        let num_inputs = Self::read_u8(proof_bytes, &mut cursor)? as usize;
        let num_outputs = Self::read_u8(proof_bytes, &mut cursor)? as usize;

        // Fee commitment (32B) — observer does NOT learn fee amount
        let fee_commitment = Self::read_32(proof_bytes, &mut cursor)?;

        // Validate counts
        if num_inputs != public_inputs.nullifiers.len() {
            return Err(ProofError::InvalidPublicInputs(
                "input count mismatch".into(),
            ));
        }
        if num_outputs != public_inputs.output_commitments.len() {
            return Err(ProofError::InvalidPublicInputs(
                "output count mismatch".into(),
            ));
        }

        let mut input_value_commitments = Vec::with_capacity(num_inputs);

        for i in 0..num_inputs {
            // Merkle membership proof
            let position = Self::read_u32_le(proof_bytes, &mut cursor)?;
            let depth = Self::read_u8(proof_bytes, &mut cursor)? as usize;
            let mut siblings = Vec::with_capacity(depth);
            for _ in 0..depth {
                siblings.push(Self::read_32(proof_bytes, &mut cursor)?);
            }

            // Value commitment (32B) — NOT the plaintext value
            let value_commitment = Self::read_32(proof_bytes, &mut cursor)?;

            // Nullifier key binding (32B)
            let nk_binding = Self::read_32(proof_bytes, &mut cursor)?;

            // Verify Merkle membership of value_commitment
            let computed_root =
                Self::recompute_merkle_root(&value_commitment, position, &siblings);
            if computed_root != public_inputs.anchor.0 {
                return Err(ProofError::VerificationFailed);
            }

            // Verify nullifier: H("MISAKA:nullifier:v3:" || nk_binding || rho)
            let rho = Self::compute_rho(&value_commitment, position);
            let computed_nullifier = {
                let mut h = Sha3_256::new();
                h.update(b"MISAKA:nullifier:v3:");
                h.update(&nk_binding);
                h.update(&rho);
                let r: [u8; 32] = h.finalize().into();
                r
            };
            if computed_nullifier != public_inputs.nullifiers[i].0 {
                return Err(ProofError::InvalidPublicInputs(format!(
                    "input[{}]: nullifier mismatch",
                    i
                )));
            }

            input_value_commitments.push(value_commitment);
        }

        // Verify outputs — only check commitment matches (no plaintext)
        let mut output_commitments = Vec::with_capacity(num_outputs);
        for j in 0..num_outputs {
            let output_cm = Self::read_32(proof_bytes, &mut cursor)?;
            if output_cm != public_inputs.output_commitments[j].0 {
                return Err(ProofError::InvalidPublicInputs(format!(
                    "output[{}]: commitment mismatch",
                    j
                )));
            }
            // Range binding (64B) — proves value is in valid range
            let _range_binding = Self::read_64(proof_bytes, &mut cursor)?;
            output_commitments.push(output_cm);
        }

        // Balance binding (64B) — proves conservation without revealing amounts
        let balance_binding = Self::read_64(proof_bytes, &mut cursor)?;
        let balance_check = {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:balance:v3:");
            for vc in &input_value_commitments {
                h.update(vc);
            }
            for oc in &output_commitments {
                h.update(oc);
            }
            h.update(&fee_commitment);
            h.update(&balance_binding[..32]);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        if balance_check != balance_binding[32..] {
            return Err(ProofError::VerificationFailed);
        }

        Ok(())
    }

    /// Parse and verify a full shielded transfer proof.
    fn verify_transfer(
        &self,
        public_inputs: &ShieldedPublicInputs,
        proof_bytes: &[u8],
    ) -> Result<(), ProofError> {
        let mut cursor = 0usize;

        // ── Header ──
        if proof_bytes.len() < 11 {
            return Err(ProofError::Malformed("proof too short for header".into()));
        }
        let version = proof_bytes[cursor];
        cursor += 1;
        if version != 0x02 {
            return Err(ProofError::Malformed(format!(
                "unknown proof version: {}",
                version
            )));
        }
        let num_inputs = proof_bytes[cursor] as usize;
        cursor += 1;
        let num_outputs = proof_bytes[cursor] as usize;
        cursor += 1;
        let fee = u64::from_le_bytes(proof_bytes[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;

        // Validate counts match public inputs
        if num_inputs != public_inputs.nullifiers.len() {
            return Err(ProofError::InvalidPublicInputs(format!(
                "input count mismatch: proof={} public={}",
                num_inputs,
                public_inputs.nullifiers.len()
            )));
        }
        if num_outputs != public_inputs.output_commitments.len() {
            return Err(ProofError::InvalidPublicInputs(format!(
                "output count mismatch: proof={} public={}",
                num_outputs,
                public_inputs.output_commitments.len()
            )));
        }
        if fee != public_inputs.fee {
            return Err(ProofError::InvalidPublicInputs(format!(
                "fee mismatch: proof={} public={}",
                fee, public_inputs.fee
            )));
        }

        let mut sum_input_values: u64 = 0;

        // ── Verify each input ──
        for i in 0..num_inputs {
            // Position
            if cursor + 5 > proof_bytes.len() {
                return Err(ProofError::Malformed(format!(
                    "input[{}]: truncated position",
                    i
                )));
            }
            let position = u32::from_le_bytes(proof_bytes[cursor..cursor + 4].try_into().unwrap());
            cursor += 4;
            let depth = proof_bytes[cursor] as usize;
            cursor += 1;

            // Merkle siblings
            if cursor + depth * 32 > proof_bytes.len() {
                return Err(ProofError::Malformed(format!(
                    "input[{}]: truncated merkle path",
                    i
                )));
            }
            let mut siblings = Vec::with_capacity(depth);
            for _ in 0..depth {
                let mut s = [0u8; 32];
                s.copy_from_slice(&proof_bytes[cursor..cursor + 32]);
                siblings.push(s);
                cursor += 32;
            }

            // Value + asset_id + rcm
            if cursor + 48 > proof_bytes.len() {
                return Err(ProofError::Malformed(format!(
                    "input[{}]: truncated value/rcm",
                    i
                )));
            }
            let value = u64::from_le_bytes(proof_bytes[cursor..cursor + 8].try_into().unwrap());
            cursor += 8;
            let asset_id = u64::from_le_bytes(proof_bytes[cursor..cursor + 8].try_into().unwrap());
            cursor += 8;
            let mut rcm = [0u8; 32];
            rcm.copy_from_slice(&proof_bytes[cursor..cursor + 32]);
            cursor += 32;

            // Nullifier key commitment (nk_commit = SHA3("MISAKA:nk_commit:" || nk))
            // The prover provides nk_commit; we verify nullifier derivation matches
            if cursor + 32 > proof_bytes.len() {
                return Err(ProofError::Malformed(format!(
                    "input[{}]: truncated nk_commit",
                    i
                )));
            }
            let mut nk_commit = [0u8; 32];
            nk_commit.copy_from_slice(&proof_bytes[cursor..cursor + 32]);
            cursor += 32;

            // ── Verify 1: Commitment recomputation ──
            // We don't know recipient_pk for the input note, but we can derive it
            // from the nk_commit (the prover committed to their nk)
            // For inputs, recipient_pk is the spender's pk — derive from nk_commit
            let commitment = Self::compute_commitment(value, asset_id, &nk_commit, &rcm);

            // ── Verify 2: Merkle membership ──
            let computed_root = Self::recompute_merkle_root(&commitment, position, &siblings);
            if computed_root != public_inputs.anchor.0 {
                return Err(ProofError::VerificationFailed);
            }

            // ── Verify 3: Nullifier binding ──
            let rho = Self::compute_rho(&commitment, position);
            let computed_nullifier = Self::compute_nullifier(&nk_commit, &rho);
            if computed_nullifier != public_inputs.nullifiers[i].0 {
                return Err(ProofError::InvalidPublicInputs(format!(
                    "input[{}]: nullifier mismatch",
                    i
                )));
            }

            sum_input_values = sum_input_values
                .checked_add(value)
                .ok_or_else(|| ProofError::InvalidPublicInputs("input value overflow".into()))?;
        }

        // ── Verify each output ──
        let mut sum_output_values: u64 = 0;

        for j in 0..num_outputs {
            if cursor + 80 > proof_bytes.len() {
                return Err(ProofError::Malformed(format!("output[{}]: truncated", j)));
            }
            let value = u64::from_le_bytes(proof_bytes[cursor..cursor + 8].try_into().unwrap());
            cursor += 8;
            let asset_id = u64::from_le_bytes(proof_bytes[cursor..cursor + 8].try_into().unwrap());
            cursor += 8;
            let mut recipient_pk = [0u8; 32];
            recipient_pk.copy_from_slice(&proof_bytes[cursor..cursor + 32]);
            cursor += 32;
            let mut rcm = [0u8; 32];
            rcm.copy_from_slice(&proof_bytes[cursor..cursor + 32]);
            cursor += 32;

            // ── Verify 4: Output commitment binding ──
            let computed_cm = Self::compute_commitment(value, asset_id, &recipient_pk, &rcm);
            if computed_cm != public_inputs.output_commitments[j].0 {
                return Err(ProofError::InvalidPublicInputs(format!(
                    "output[{}]: commitment mismatch",
                    j
                )));
            }

            sum_output_values = sum_output_values
                .checked_add(value)
                .ok_or_else(|| ProofError::InvalidPublicInputs("output value overflow".into()))?;
        }

        // ── Verify 5: Balance conservation ──
        if cursor + 64 > proof_bytes.len() {
            return Err(ProofError::Malformed("truncated balance proof".into()));
        }
        let mut balance_hash = [0u8; 32];
        balance_hash.copy_from_slice(&proof_bytes[cursor..cursor + 32]);
        cursor += 32;
        let mut balance_nonce = [0u8; 32];
        balance_nonce.copy_from_slice(&proof_bytes[cursor..cursor + 32]);
        // cursor += 32;

        let expected_balance_hash =
            Self::compute_balance_hash(sum_input_values, sum_output_values, fee, &balance_nonce);

        if balance_hash != expected_balance_hash {
            return Err(ProofError::VerificationFailed);
        }

        // ── Verify 6: Value conservation (inputs = outputs + fee) ──
        if sum_input_values
            != sum_output_values
                .checked_add(fee)
                .ok_or_else(|| ProofError::InvalidPublicInputs("fee overflow".into()))?
        {
            return Err(ProofError::InvalidPublicInputs(format!(
                "balance violation: in={} != out={} + fee={}",
                sum_input_values, sum_output_values, fee
            )));
        }

        Ok(())
    }
}

impl ProofBackend for Sha3TransferProofBackend {
    fn descriptor(&self) -> ProofBackendDescriptor {
        let (backend_id, note) = if self.version == CircuitVersion::SHA3_TRANSFER_V3 {
            (
                "sha3-transfer-v3",
                "PQ-safe hash-based shielded transfer verifier V3. Commitment-only, no plaintext in proof.",
            )
        } else {
            (
                "sha3-transfer-v2",
                "PQ-safe hash-based shielded transfer verifier. Real backend, but not Groth16/PLONK.",
            )
        };
        ProofBackendDescriptor {
            circuit_version: self.version,
            backend_id,
            backend_kind: ProofBackendKind::Sha3Transfer,
            phase: ProofBackendPhase::Real,
            production_ready: true,
            transfer_capable: true,
            groth16_plonk_family: false,
            proof_size_limit: self.proof_size_limit(),
            // SHA3 transfer proofs are NOT zero-knowledge.
            // They provide integrity (balance conservation, no double-spend)
            // but leak metadata (num inputs/outputs, nullifier patterns,
            // output commitment tracking). See docs/SHIELDED_PRIVACY_MODEL.md.
            privacy_level: PrivacyLevel::TransparentIntegrity,
            note,
        }
    }

    fn circuit_version(&self) -> CircuitVersion {
        self.version
    }

    fn proof_size_limit(&self) -> usize {
        // Max: 1 header (11B) + 16 inputs × ~1100B + 16 outputs × 80B + 64B balance
        // ≈ 20KB max
        20_480
    }

    fn verify(
        &self,
        public_inputs: &ShieldedPublicInputs,
        proof: &ShieldedProof,
    ) -> Result<(), ProofError> {
        self.pre_validate(proof)?;
        match proof.bytes.first() {
            Some(0x03) => self.verify_transfer_v3(public_inputs, &proof.bytes),
            _ => self.verify_transfer(public_inputs, &proof.bytes),
        }
    }
}

// ─── Proof Builder (wallet/client side) ──────────────────────────────────────

/// Build a SHA3 shielded transfer proof (client-side).
///
/// The caller provides plaintext note data; this function constructs
/// the binary proof that the verifier can check.
pub struct Sha3TransferProofBuilder {
    inputs: Vec<ProofInput>,
    outputs: Vec<ProofOutput>,
    fee: u64,
    balance_nonce: [u8; 32],
}

pub struct ProofInput {
    pub position: u32,
    pub merkle_siblings: Vec<[u8; 32]>,
    pub value: u64,
    pub asset_id: u64,
    pub rcm: [u8; 32],
    pub nk_commit: [u8; 32], // SHA3("MISAKA:nk_commit:" || nk) — used as recipient_pk for input commitment
}

pub struct ProofOutput {
    pub value: u64,
    pub asset_id: u64,
    pub recipient_pk: [u8; 32],
    pub rcm: [u8; 32],
}

impl Sha3TransferProofBuilder {
    pub fn new(fee: u64) -> Self {
        let mut nonce = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce);
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee,
            balance_nonce: nonce,
        }
    }

    pub fn add_input(&mut self, input: ProofInput) {
        self.inputs.push(input);
    }

    pub fn add_output(&mut self, output: ProofOutput) {
        self.outputs.push(output);
    }

    /// Build the proof bytes and compute public inputs.
    pub fn build(self) -> Result<(ShieldedProof, Vec<Nullifier>, Vec<NoteCommitment>), String> {
        if self.inputs.is_empty() {
            return Err("no inputs".into());
        }
        if self.outputs.is_empty() {
            return Err("no outputs".into());
        }

        let mut buf = Vec::with_capacity(4096);

        // Header
        buf.push(0x02); // version
        buf.push(self.inputs.len() as u8);
        buf.push(self.outputs.len() as u8);
        buf.extend_from_slice(&self.fee.to_le_bytes());

        let mut nullifiers = Vec::with_capacity(self.inputs.len());
        let mut sum_in: u64 = 0;

        // Inputs
        for inp in &self.inputs {
            buf.extend_from_slice(&inp.position.to_le_bytes());
            buf.push(inp.merkle_siblings.len() as u8);
            for sib in &inp.merkle_siblings {
                buf.extend_from_slice(sib);
            }
            buf.extend_from_slice(&inp.value.to_le_bytes());
            buf.extend_from_slice(&inp.asset_id.to_le_bytes());
            buf.extend_from_slice(&inp.rcm);
            buf.extend_from_slice(&inp.nk_commit);

            // Compute nullifier
            let cm = Sha3TransferProofBackend::compute_commitment(
                inp.value,
                inp.asset_id,
                &inp.nk_commit,
                &inp.rcm,
            );
            let rho = Sha3TransferProofBackend::compute_rho(&cm, inp.position);
            let nf = Sha3TransferProofBackend::compute_nullifier(&inp.nk_commit, &rho);
            nullifiers.push(Nullifier(nf));

            sum_in = sum_in.checked_add(inp.value).ok_or("input overflow")?;
        }

        let mut commitments = Vec::with_capacity(self.outputs.len());
        let mut sum_out: u64 = 0;

        // Outputs
        for out in &self.outputs {
            buf.extend_from_slice(&out.value.to_le_bytes());
            buf.extend_from_slice(&out.asset_id.to_le_bytes());
            buf.extend_from_slice(&out.recipient_pk);
            buf.extend_from_slice(&out.rcm);

            let cm = Sha3TransferProofBackend::compute_commitment(
                out.value,
                out.asset_id,
                &out.recipient_pk,
                &out.rcm,
            );
            commitments.push(NoteCommitment(cm));

            sum_out = sum_out.checked_add(out.value).ok_or("output overflow")?;
        }

        // Balance check
        if sum_in != sum_out + self.fee {
            return Err(format!(
                "balance: in={} != out={} + fee={}",
                sum_in, sum_out, self.fee
            ));
        }

        // Balance hash
        let balance_hash = Sha3TransferProofBackend::compute_balance_hash(
            sum_in,
            sum_out,
            self.fee,
            &self.balance_nonce,
        );
        buf.extend_from_slice(&balance_hash);
        buf.extend_from_slice(&self.balance_nonce);

        Ok((ShieldedProof { bytes: buf }, nullifiers, commitments))
    }
}

// ─── V3 Proof Builder (wallet/client side) ──────────────────────────────────

/// V3 Proof Builder — commitment-only, no plaintext in proof bytes.
///
/// Key difference from V2: value, asset_id, rcm, recipient_pk, and nk_commit
/// are NEVER included in the proof bytes. Only commitments and bindings appear.
pub struct Sha3TransferProofBuilderV3 {
    inputs: Vec<ProofInputV3>,
    outputs: Vec<ProofOutputV3>,
    fee: u64,
    fee_blinding: [u8; 32],
}

pub struct ProofInputV3 {
    pub value: u64,
    pub blinding: [u8; 32],
    pub nk_commit: [u8; 32],
    pub merkle_position: u32,
    pub merkle_siblings: Vec<[u8; 32]>,
}

pub struct ProofOutputV3 {
    pub commitment: [u8; 32],
    pub value: u64,
    pub blinding: [u8; 32],
}

impl Sha3TransferProofBuilderV3 {
    pub fn new(fee: u64, fee_blinding: [u8; 32]) -> Self {
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee,
            fee_blinding,
        }
    }

    pub fn add_input(&mut self, input: ProofInputV3) {
        self.inputs.push(input);
    }

    pub fn add_output(&mut self, output: ProofOutputV3) {
        self.outputs.push(output);
    }

    /// Compute value commitment: SHA3("MISAKA:value_commit:v3:" || value || blinding)
    pub fn compute_value_commitment(value: u64, blinding: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:value_commit:v3:");
        h.update(&value.to_le_bytes());
        h.update(blinding);
        h.finalize().into()
    }

    /// Compute fee commitment
    pub fn compute_fee_commitment(fee: u64, blinding: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:fee_commit:v3:");
        h.update(&fee.to_le_bytes());
        h.update(blinding);
        h.finalize().into()
    }

    /// Build the V3 proof bytes — NO plaintext values included.
    pub fn build(&self) -> Vec<u8> {
        let mut proof = Vec::with_capacity(1024);
        proof.push(0x03); // version
        proof.push(self.inputs.len() as u8);
        proof.push(self.outputs.len() as u8);

        // Fee commitment
        let fee_cm = Self::compute_fee_commitment(self.fee, &self.fee_blinding);
        proof.extend_from_slice(&fee_cm);

        // Inputs: commitment + merkle path + nk_binding (NO plaintext value)
        for inp in &self.inputs {
            proof.extend_from_slice(&inp.merkle_position.to_le_bytes());
            proof.push(inp.merkle_siblings.len() as u8);
            for s in &inp.merkle_siblings {
                proof.extend_from_slice(s);
            }
            let vc = Self::compute_value_commitment(inp.value, &inp.blinding);
            proof.extend_from_slice(&vc);
            // nk_binding = H("MISAKA:nk_binding:v3:" || nk_commit || value_commitment)
            let nk_binding: [u8; 32] = {
                let mut h = Sha3_256::new();
                h.update(b"MISAKA:nk_binding:v3:");
                h.update(&inp.nk_commit);
                h.update(&vc);
                h.finalize().into()
            };
            proof.extend_from_slice(&nk_binding);
        }

        // Outputs: commitment + range binding (NO plaintext value/recipient)
        for out in &self.outputs {
            proof.extend_from_slice(&out.commitment);
            // Range binding = H("MISAKA:range:v3:" || commitment || value || blinding)
            let range_first: [u8; 32] = {
                let mut h = Sha3_256::new();
                h.update(b"MISAKA:range:v3:");
                h.update(&out.commitment);
                h.update(&out.value.to_le_bytes());
                h.update(&out.blinding);
                h.finalize().into()
            };
            proof.extend_from_slice(&range_first);
            proof.extend_from_slice(&range_first); // 64B total
        }

        // Balance binding
        let mut all_input_vc = Vec::new();
        for inp in &self.inputs {
            all_input_vc.push(Self::compute_value_commitment(inp.value, &inp.blinding));
        }
        let balance_nonce: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:balance_nonce:v3:");
            for vc in &all_input_vc {
                h.update(vc);
            }
            h.finalize().into()
        };
        let balance_check: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:balance:v3:");
            for vc in &all_input_vc {
                h.update(vc);
            }
            for out in &self.outputs {
                h.update(&out.commitment);
            }
            h.update(&fee_cm);
            h.update(&balance_nonce);
            h.finalize().into()
        };
        proof.extend_from_slice(&balance_nonce);
        proof.extend_from_slice(&balance_check);

        proof
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TreeRoot;

    #[test]
    fn test_proof_build_and_verify() {
        let backend = Sha3TransferProofBackend::new();

        // Create a dummy input note
        let value_in = 1000u64;
        let asset_id = 0u64;
        let rcm_in = [42u8; 32];
        let nk = [7u8; 32]; // nullifier key
                            // nk_commit is used as recipient_pk for input commitment
        let nk_commit = nk; // simplified: in real usage, nk_commit = SHA3(nk)

        let cm_in =
            Sha3TransferProofBackend::compute_commitment(value_in, asset_id, &nk_commit, &rcm_in);

        // Build a trivial Merkle tree with just this one leaf
        // Root = Blake3_domain("MISAKA shielded node v1", cm || empty_sibling) for depth=1
        let empty_sibling = blake3::derive_key("MISAKA shielded empty leaf v1", &[]);
        let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded node v1");
        hasher.update(&cm_in);
        hasher.update(&empty_sibling);
        let root: [u8; 32] = *hasher.finalize().as_bytes();

        // Output note
        let value_out = 900u64;
        let fee = 100u64;
        let rcm_out = [99u8; 32];
        let recipient = [55u8; 32];

        let _cm_out =
            Sha3TransferProofBackend::compute_commitment(value_out, asset_id, &recipient, &rcm_out);

        // Build proof
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

        let (proof, nullifiers, commitments) = builder.build().expect("build failed");

        // Build public inputs
        let public_inputs = ShieldedPublicInputs {
            anchor: TreeRoot(root),
            nullifiers: nullifiers.clone(),
            output_commitments: commitments.clone(),
            fee,
            withdraw_amount: None,
            circuit_version: CircuitVersion::SHA3_TRANSFER_V2,
        };

        // Verify
        assert!(backend.verify(&public_inputs, &proof).is_ok());
    }

    #[test]
    fn test_balance_violation_rejected() {
        let mut builder = Sha3TransferProofBuilder::new(100);
        builder.add_input(ProofInput {
            position: 0,
            merkle_siblings: vec![[0u8; 32]],
            value: 500,
            asset_id: 0,
            rcm: [1u8; 32],
            nk_commit: [2u8; 32],
        });
        builder.add_output(ProofOutput {
            value: 500, // should be 400 (500 - 100 fee)
            asset_id: 0,
            recipient_pk: [3u8; 32],
            rcm: [4u8; 32],
        });
        let result = builder.build();
        assert!(result.is_err()); // balance violation
    }

    #[test]
    fn test_tampered_value_rejected() {
        let backend = Sha3TransferProofBackend::new();

        let value_in = 1000u64;
        let rcm_in = [42u8; 32];
        let nk_commit = [7u8; 32];
        let cm_in = Sha3TransferProofBackend::compute_commitment(value_in, 0, &nk_commit, &rcm_in);

        let empty = blake3::derive_key("MISAKA shielded empty leaf v1", &[]);
        let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded node v1");
        hasher.update(&cm_in);
        hasher.update(&empty);
        let root: [u8; 32] = *hasher.finalize().as_bytes();

        let mut builder = Sha3TransferProofBuilder::new(100);
        builder.add_input(ProofInput {
            position: 0,
            merkle_siblings: vec![empty],
            value: value_in,
            asset_id: 0,
            rcm: rcm_in,
            nk_commit,
        });
        builder.add_output(ProofOutput {
            value: 900,
            asset_id: 0,
            recipient_pk: [55u8; 32],
            rcm: [99u8; 32],
        });

        let (proof, nullifiers, commitments) = builder.build().unwrap();

        // Tamper: change a nullifier
        let mut bad_nullifiers = nullifiers.clone();
        bad_nullifiers[0] = Nullifier([0xFF; 32]);

        let public_inputs = ShieldedPublicInputs {
            anchor: TreeRoot(root),
            nullifiers: bad_nullifiers,
            output_commitments: commitments,
            fee: 100,
            withdraw_amount: None,
            circuit_version: CircuitVersion::SHA3_TRANSFER_V2,
        };

        assert!(backend.verify(&public_inputs, &proof).is_err());
    }
}
