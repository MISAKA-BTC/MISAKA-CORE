//! LRS Adapter — wraps existing pq_ring::* behind the RingScheme trait.
//!
//! This is the legacy v1 implementation. All existing behavior is preserved.
//! New code should use the trait interface; direct pq_ring calls are deprecated.

use crate::error::CryptoError;
use crate::ring_scheme::{RingScheme, BatchVerifiable};
use crate::pq_ring::{
    Poly, RingSig, SpendingKeypair,
    ring_sign as lrs_ring_sign,
    ring_verify as lrs_ring_verify,
    derive_public_param, DEFAULT_A_SEED,
    compute_key_image as lrs_compute_key_image,
    MIN_RING_SIZE, MAX_RING_SIZE, N,
};
use crate::ki_proof::{
    KiProof,
    prove_key_image as lrs_prove_ki,
    verify_key_image_proof as lrs_verify_ki,
};

/// LRS implementation of RingScheme.
pub struct LrsScheme {
    /// Shared public parameter 'a' (derived from seed).
    a: Poly,
}

impl LrsScheme {
    /// Create with default parameter seed.
    pub fn new() -> Self {
        Self { a: derive_public_param(&DEFAULT_A_SEED) }
    }

    /// Create with custom seed (for testing).
    pub fn with_seed(seed: &[u8; 32]) -> Self {
        Self { a: derive_public_param(seed) }
    }

    /// Get the shared parameter (for direct access if needed).
    pub fn shared_param(&self) -> &Poly {
        &self.a
    }
}

impl Default for LrsScheme {
    fn default() -> Self { Self::new() }
}

impl RingScheme for LrsScheme {
    type PublicKey = Poly;
    type SecretKey = Poly;
    type Signature = RingSig;
    type KiProof = KiProof;

    fn scheme_id(&self) -> &'static str { "LRS-v1" }

    fn derive_pubkey(&self, sk: &Poly) -> Poly {
        self.a.mul(sk)
    }

    fn compute_key_image(&self, sk: &Poly) -> [u8; 32] {
        // Use canonical (scheme-independent) KI for cross-scheme double-spend prevention
        crate::canonical_ki::canonical_key_image(sk)
    }

    fn ring_sign(
        &self,
        ring_pubkeys: &[Poly],
        signer_index: usize,
        sk: &Poly,
        message: &[u8; 32],
    ) -> Result<RingSig, CryptoError> {
        lrs_ring_sign(&self.a, ring_pubkeys, signer_index, sk, message)
    }

    fn ring_verify(
        &self,
        ring_pubkeys: &[Poly],
        message: &[u8; 32],
        signature: &RingSig,
    ) -> Result<(), CryptoError> {
        lrs_ring_verify(&self.a, ring_pubkeys, message, signature)
    }

    fn prove_key_image(
        &self,
        sk: &Poly,
        pk: &Poly,
        key_image: &[u8; 32],
    ) -> Result<KiProof, CryptoError> {
        lrs_prove_ki(&self.a, sk, pk, key_image)
    }

    fn verify_key_image_proof(
        &self,
        pk: &Poly,
        key_image: &[u8; 32],
        proof: &KiProof,
    ) -> Result<(), CryptoError> {
        lrs_verify_ki(&self.a, pk, key_image, proof)
    }

    fn signature_to_bytes(&self, sig: &RingSig) -> Vec<u8> {
        sig.to_bytes()
    }

    fn signature_from_bytes(&self, data: &[u8], ring_size: usize) -> Result<RingSig, CryptoError> {
        RingSig::from_bytes(data, ring_size)
    }

    fn pubkey_to_bytes(&self, pk: &Poly) -> Vec<u8> {
        pk.to_bytes()
    }

    fn pubkey_from_bytes(&self, data: &[u8]) -> Result<Poly, CryptoError> {
        Poly::from_bytes(data)
    }

    fn ki_proof_to_bytes(&self, proof: &KiProof) -> Vec<u8> {
        proof.to_bytes()
    }

    fn ki_proof_from_bytes(&self, data: &[u8]) -> Result<KiProof, CryptoError> {
        KiProof::from_bytes(data)
    }

    fn min_ring_size(&self) -> usize { MIN_RING_SIZE }
    fn max_ring_size(&self) -> usize { MAX_RING_SIZE }
}

impl BatchVerifiable for LrsScheme {}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_sign::MlDsaKeypair;
    use crate::pq_ring::{derive_secret_poly, compute_pubkey};

    fn make_keypair(scheme: &LrsScheme) -> (Poly, Poly, [u8; 32]) {
        let kp = MlDsaKeypair::generate();
        let sk = derive_secret_poly(&kp.secret_key).unwrap();
        let pk = compute_pubkey(scheme.shared_param(), &sk);
        let ki = scheme.compute_key_image(&sk);
        (sk, pk, ki)
    }

    #[test]
    fn test_lrs_trait_sign_verify() {
        let scheme = LrsScheme::new();
        let (sk0, pk0, _ki0) = make_keypair(&scheme);
        let (_, pk1, _) = make_keypair(&scheme);
        let (_, pk2, _) = make_keypair(&scheme);
        let (_, pk3, _) = make_keypair(&scheme);

        let ring = vec![pk0.clone(), pk1, pk2, pk3];
        let msg = [0x42u8; 32];

        let sig = scheme.ring_sign(&ring, 0, &sk0, &msg).unwrap();
        scheme.ring_verify(&ring, &msg, &sig).unwrap();
    }

    #[test]
    fn test_lrs_trait_ki_proof() {
        let scheme = LrsScheme::new();
        let (sk, pk, _legacy_ki) = make_keypair(&scheme);

        // KI proof uses algebraic strong-binding key image (h_pk * s),
        // NOT the legacy SHA3-based canonical_key_image.
        let (_, strong_ki) = crate::ki_proof::canonical_strong_ki(&pk, &sk);
        let proof = scheme.prove_key_image(&sk, &pk, &strong_ki).unwrap();
        scheme.verify_key_image_proof(&pk, &strong_ki, &proof).unwrap();
    }

    #[test]
    fn test_lrs_trait_serialization_roundtrip() {
        let scheme = LrsScheme::new();
        let (sk0, pk0, _) = make_keypair(&scheme);
        let (_, pk1, _) = make_keypair(&scheme);
        let (_, pk2, _) = make_keypair(&scheme);
        let (_, pk3, _) = make_keypair(&scheme);

        let ring = vec![pk0, pk1, pk2, pk3];
        let msg = [0xAA; 32];
        let sig = scheme.ring_sign(&ring, 0, &sk0, &msg).unwrap();

        let bytes = scheme.signature_to_bytes(&sig);
        let sig2 = scheme.signature_from_bytes(&bytes, 4).unwrap();
        scheme.ring_verify(&ring, &msg, &sig2).unwrap();
    }

    #[test]
    fn test_lrs_key_image_deterministic() {
        let scheme = LrsScheme::new();
        let (sk, _, _) = make_keypair(&scheme);
        let ki1 = scheme.compute_key_image(&sk);
        let ki2 = scheme.compute_key_image(&sk);
        assert_eq!(ki1, ki2);
    }

    #[test]
    fn test_lrs_scheme_id() {
        let scheme = LrsScheme::new();
        assert_eq!(scheme.scheme_id(), "LRS-v1");
    }
}
