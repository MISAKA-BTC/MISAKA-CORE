//! ChipmunkRing Adapter — implements RingScheme trait for ChipmunkRing.

use crate::error::CryptoError;
use crate::ring_scheme::{RingScheme, BatchVerifiable};
use crate::pq_ring::{Poly, derive_public_param, DEFAULT_A_SEED};
use crate::chipmunk::*;

/// ChipmunkRing implementation of RingScheme.
pub struct ChipmunkScheme {
    a: Poly,
}

impl ChipmunkScheme {
    pub fn new() -> Self {
        Self { a: derive_public_param(&DEFAULT_A_SEED) }
    }

    pub fn with_seed(seed: &[u8; 32]) -> Self {
        Self { a: derive_public_param(seed) }
    }

    pub fn shared_param(&self) -> &Poly { &self.a }
}

impl Default for ChipmunkScheme {
    fn default() -> Self { Self::new() }
}

impl RingScheme for ChipmunkScheme {
    type PublicKey = Poly;
    type SecretKey = Poly;
    type Signature = ChipmunkSig;
    type KiProof = ChipmunkKiProof;

    fn scheme_id(&self) -> &'static str { "Chipmunk-v1" }

    fn derive_pubkey(&self, sk: &Poly) -> Poly {
        self.a.mul(sk)
    }

    fn compute_key_image(&self, sk: &Poly) -> [u8; 32] {
        // Use canonical (scheme-independent) KI for cross-scheme double-spend prevention
        crate::canonical_ki::canonical_key_image(sk)
    }

    fn ring_sign(
        &self, ring_pubkeys: &[Poly], signer_index: usize, sk: &Poly, message: &[u8; 32],
    ) -> Result<ChipmunkSig, CryptoError> {
        chipmunk_ring_sign(&self.a, ring_pubkeys, signer_index, sk, message)
    }

    fn ring_verify(
        &self, ring_pubkeys: &[Poly], message: &[u8; 32], signature: &ChipmunkSig,
    ) -> Result<(), CryptoError> {
        chipmunk_ring_verify(&self.a, ring_pubkeys, message, signature)
    }

    fn prove_key_image(
        &self, sk: &Poly, pk: &Poly, key_image: &[u8; 32],
    ) -> Result<ChipmunkKiProof, CryptoError> {
        chipmunk_prove_ki(&self.a, sk, pk, key_image)
    }

    fn verify_key_image_proof(
        &self, pk: &Poly, key_image: &[u8; 32], proof: &ChipmunkKiProof,
    ) -> Result<(), CryptoError> {
        chipmunk_verify_ki(&self.a, pk, key_image, proof)
    }

    fn signature_to_bytes(&self, sig: &ChipmunkSig) -> Vec<u8> { sig.to_bytes() }
    fn signature_from_bytes(&self, data: &[u8], ring_size: usize) -> Result<ChipmunkSig, CryptoError> {
        ChipmunkSig::from_bytes(data, ring_size)
    }
    fn pubkey_to_bytes(&self, pk: &Poly) -> Vec<u8> { pk.to_bytes() }
    fn pubkey_from_bytes(&self, data: &[u8]) -> Result<Poly, CryptoError> { Poly::from_bytes(data) }
    fn ki_proof_to_bytes(&self, proof: &ChipmunkKiProof) -> Vec<u8> { proof.to_bytes() }
    fn ki_proof_from_bytes(&self, data: &[u8]) -> Result<ChipmunkKiProof, CryptoError> {
        ChipmunkKiProof::from_bytes(data)
    }

    fn min_ring_size(&self) -> usize { CR_MIN_RING }
    fn max_ring_size(&self) -> usize { CR_MAX_RING }
}

impl BatchVerifiable for ChipmunkScheme {}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ring_scheme::RingScheme;
    use crate::pq_sign::MlDsaKeypair;
    use crate::pq_ring::derive_secret_poly;

    fn make_kp(scheme: &ChipmunkScheme) -> (Poly, Poly, [u8; 32]) {
        let kp = MlDsaKeypair::generate();
        let sk = derive_secret_poly(&kp.secret_key);
        let pk = scheme.derive_pubkey(&sk);
        let ki = scheme.compute_key_image(&sk);
        (sk, pk, ki)
    }

    #[test]
    fn test_chipmunk_trait_sign_verify() {
        let scheme = ChipmunkScheme::new();
        let (sk0, pk0, _) = make_kp(&scheme);
        let (_, pk1, _) = make_kp(&scheme);
        let (_, pk2, _) = make_kp(&scheme);
        let (_, pk3, _) = make_kp(&scheme);

        let ring = vec![pk0, pk1, pk2, pk3];
        let msg = [0x42u8; 32];
        let sig = scheme.ring_sign(&ring, 0, &sk0, &msg).unwrap();
        scheme.ring_verify(&ring, &msg, &sig).unwrap();
    }

    #[test]
    fn test_chipmunk_trait_ki_proof() {
        let scheme = ChipmunkScheme::new();
        let (sk, pk, ki) = make_kp(&scheme);
        let proof = scheme.prove_key_image(&sk, &pk, &ki).unwrap();
        scheme.verify_key_image_proof(&pk, &ki, &proof).unwrap();
    }

    #[test]
    fn test_chipmunk_trait_serialization() {
        let scheme = ChipmunkScheme::new();
        let (sk0, pk0, _) = make_kp(&scheme);
        let (_, pk1, _) = make_kp(&scheme);
        let (_, pk2, _) = make_kp(&scheme);
        let (_, pk3, _) = make_kp(&scheme);

        let ring = vec![pk0, pk1, pk2, pk3];
        let msg = [0xBB; 32];
        let sig = scheme.ring_sign(&ring, 0, &sk0, &msg).unwrap();
        let bytes = scheme.signature_to_bytes(&sig);
        let sig2 = scheme.signature_from_bytes(&bytes, 4).unwrap();
        scheme.ring_verify(&ring, &msg, &sig2).unwrap();
    }

    #[test]
    fn test_chipmunk_scheme_id() {
        let scheme = ChipmunkScheme::new();
        assert_eq!(scheme.scheme_id(), "Chipmunk-v1");
    }

    #[test]
    fn test_chipmunk_max_ring_32() {
        let scheme = ChipmunkScheme::new();
        assert_eq!(scheme.max_ring_size(), 32);
    }

    /// CRITICAL: Same secret → same KI across LRS and ChipmunkRing.
    /// This prevents cross-scheme double-spend attacks.
    #[test]
    fn test_cross_scheme_canonical_ki() {
        use crate::lrs_adapter::LrsScheme;

        let lrs = LrsScheme::new();
        let chipmunk = ChipmunkScheme::new();

        let kp = MlDsaKeypair::generate();
        let sk = derive_secret_poly(&kp.secret_key);

        let ki_lrs = lrs.compute_key_image(&sk);
        let ki_chipmunk = chipmunk.compute_key_image(&sk);

        assert_eq!(ki_lrs, ki_chipmunk,
            "LRS and ChipmunkRing must produce identical KI from the same secret");
    }
}
