//! PQ-only handshake with MUTUAL authentication.
//!
//! Protocol (ECC-free, ML-KEM-768 + ML-DSA-65):
//! 1. Initiator → Responder: ephemeral ML-KEM-768 PK
//! 2. Responder: encapsulate → ciphertext + shared secret
//! 3. Responder → Initiator: ciphertext + responder PQ PK + PQ sig
//! 4. Both derive session key from shared secret
//! 5. Initiator: signs transcript with ML-DSA-65 → sends sig
//! 6. Responder: signs transcript with ML-DSA-65 → sends sig
//! 7. Both verify each other's signatures → mutual auth complete
//!
//! No ECC (Ed25519, secp256k1) is used anywhere.

use misaka_crypto::validator_sig::{
    validator_sign, validator_verify, ValidatorPqPublicKey, ValidatorPqSecretKey,
    ValidatorPqSignature,
};
use misaka_pqc::error::CryptoError;
use misaka_pqc::pq_kem::{kdf_derive, ml_kem_decapsulate, ml_kem_encapsulate, ml_kem_keygen};
use misaka_pqc::pq_kem::{MlKemCiphertext, MlKemPublicKey, MlKemSecretKey};

const DST_SESSION: &[u8] = b"MISAKA-v2:p2p:session-key:";
const DST_TRANSCRIPT: &[u8] = b"MISAKA-v2:p2p:transcript:";

/// Completed handshake result.
pub struct HandshakeResult {
    pub session_key: [u8; 32],
    pub peer_pk: ValidatorPqPublicKey,
    /// Initiator's ML-DSA-65 signature over the transcript.
    /// MUST be sent to the responder for mutual authentication.
    pub our_signature: ValidatorPqSignature,
}

/// Initiator's handshake state.
pub struct InitiatorHandshake {
    pub ephemeral_pk: MlKemPublicKey,
    ephemeral_sk: MlKemSecretKey,
    pub identity_pk: ValidatorPqPublicKey,
}

/// Responder's reply (sent to initiator).
pub struct ResponderReply {
    pub ciphertext: MlKemCiphertext,
    pub responder_pk: ValidatorPqPublicKey,
    pub responder_sig: ValidatorPqSignature,
    session_key: [u8; 32],
    /// Transcript needed for verifying initiator's signature in step 7.
    transcript: Vec<u8>,
}

impl ResponderReply {
    /// Step 7: Responder verifies initiator's signature to complete mutual auth.
    ///
    /// After receiving the initiator's signature (from HandshakeResult::our_signature),
    /// the responder MUST call this to verify the initiator's identity.
    /// If this fails, the connection MUST be immediately dropped.
    ///
    /// Returns the session key + verified initiator public key on success.
    pub fn verify_initiator(
        &self,
        initiator_sig: &ValidatorPqSignature,
        initiator_pk: &ValidatorPqPublicKey,
    ) -> Result<HandshakeResult, CryptoError> {
        // Verify initiator's ML-DSA-65 signature over the same transcript
        validator_verify(&self.transcript, initiator_sig, initiator_pk)
            .map_err(|_| CryptoError::MlKemDecapsulateFailed)?;

        Ok(HandshakeResult {
            session_key: self.session_key,
            peer_pk: initiator_pk.clone(),
            // Responder's own signature was already sent in ResponderReply
            our_signature: self.responder_sig.clone(),
        })
    }
}

impl InitiatorHandshake {
    /// Step 1: Initiator generates ephemeral KEM keypair.
    pub fn new(identity_pk: ValidatorPqPublicKey) -> Result<Self, CryptoError> {
        let kp = ml_kem_keygen()?;
        Ok(Self {
            ephemeral_pk: kp.public_key,
            ephemeral_sk: kp.secret_key,
            identity_pk,
        })
    }

    /// Step 5: Initiator completes handshake with MANDATORY peer identity verification.
    ///
    /// # Production Safety
    ///
    /// The expected responder public key is REQUIRED. This prevents MITM attacks
    /// by ensuring the responder is the validator the initiator intended to connect to.
    /// The public key must come from the validator set or peer registry.
    pub fn complete_verified(
        self,
        reply: &ResponderReply,
        identity_sk: &ValidatorPqSecretKey,
        expected_responder_pk: &ValidatorPqPublicKey,
    ) -> Result<HandshakeResult, CryptoError> {
        // Verify responder identity BEFORE decapsulation
        if &reply.responder_pk != expected_responder_pk {
            return Err(CryptoError::MlKemDecapsulateFailed);
        }

        self.complete_inner(reply, identity_sk)
    }

    /// Step 5 (DEV ONLY): Complete handshake WITHOUT peer identity verification.
    ///
    /// # Safety
    ///
    /// This skips MITM protection. Only available in dev builds.
    /// **NEVER** use in production — an attacker can impersonate any peer.
    #[cfg(feature = "dev")]
    pub fn complete_unverified_for_dev(
        self,
        reply: &ResponderReply,
        identity_sk: &ValidatorPqSecretKey,
    ) -> Result<HandshakeResult, CryptoError> {
        tracing::warn!("⚠ PQ handshake: completing WITHOUT peer identity verification (dev mode)");
        self.complete_inner(reply, identity_sk)
    }

    /// Internal handshake completion (shared logic).
    fn complete_inner(
        self,
        reply: &ResponderReply,
        identity_sk: &ValidatorPqSecretKey,
    ) -> Result<HandshakeResult, CryptoError> {
        // Decapsulate
        let ss = ml_kem_decapsulate(&self.ephemeral_sk, &reply.ciphertext)?;
        let session_key = kdf_derive(&ss, DST_SESSION, 0);

        // Build transcript for mutual auth
        let transcript = build_transcript(&self.ephemeral_pk, &reply.ciphertext, &session_key);

        // Verify responder's PQ signature on transcript
        validator_verify(&transcript, &reply.responder_sig, &reply.responder_pk)
            .map_err(|_| CryptoError::MlKemDecapsulateFailed)?;

        // Sign transcript ourselves (initiator auth) — MUST be sent to responder
        let our_sig = validator_sign(&transcript, identity_sk)
            .map_err(|_| CryptoError::MlKemDecapsulateFailed)?;

        Ok(HandshakeResult {
            session_key,
            peer_pk: reply.responder_pk.clone(),
            our_signature: our_sig,
        })
    }
}

/// Step 2-4: Responder handles initiator's ephemeral PK.
///
/// After calling this, the responder MUST:
/// 1. Send the reply (ciphertext + pk + sig) to the initiator
/// 2. Receive the initiator's signature + pk
/// 3. Call reply.verify_initiator() to complete mutual auth
/// 4. If verify_initiator() fails → DROP the connection immediately
pub fn responder_handle(
    initiator_kem_pk: &MlKemPublicKey,
    identity_pk: ValidatorPqPublicKey,
    identity_sk: &ValidatorPqSecretKey,
) -> Result<ResponderReply, CryptoError> {
    let (ct, ss) = ml_kem_encapsulate(initiator_kem_pk)?;
    let session_key = kdf_derive(&ss, DST_SESSION, 0);

    let transcript = build_transcript(initiator_kem_pk, &ct, &session_key);
    let sig = validator_sign(&transcript, identity_sk)
        .map_err(|_| CryptoError::MlKemEncapsulateFailed)?;

    Ok(ResponderReply {
        ciphertext: ct,
        responder_pk: identity_pk,
        responder_sig: sig,
        session_key,
        transcript,
    })
}

/// Build the mutual authentication transcript.
///
/// # Security (SEC-TRANSCRIPT fix)
///
/// The transcript binds the KEM public key and ciphertext (public values),
/// NOT the derived session key. Including the session key in signed data
/// would create a circular dependency and allow transcript replay if the
/// session key ever leaks. The KEM ciphertext already uniquely identifies
/// the key exchange session.
///
/// `transcript = DST_TRANSCRIPT || kem_pk_bytes || ciphertext_bytes`
fn build_transcript(
    kem_pk: &MlKemPublicKey,
    ct: &MlKemCiphertext,
    _session_key: &[u8; 32],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(DST_TRANSCRIPT.len() + 1184 + 1088);
    t.extend_from_slice(DST_TRANSCRIPT);
    t.extend_from_slice(kem_pk.as_bytes());
    t.extend_from_slice(ct.as_bytes());
    // NOTE: session_key deliberately excluded from transcript.
    // Signing derived secrets creates circular dependency and leaks
    // transcript verifiability if session key is compromised.
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_crypto::validator_sig::generate_validator_keypair;

    #[test]
    fn test_mutual_auth_handshake() {
        let initiator_kp = generate_validator_keypair();
        let responder_kp = generate_validator_keypair();

        // Step 1: Initiator generates ephemeral KEM keypair
        let hs = InitiatorHandshake::new(initiator_kp.public_key.clone()).unwrap();
        let initiator_kem_pk = hs.ephemeral_pk.clone();

        // Steps 2-4: Responder encapsulates + signs transcript
        let reply = responder_handle(
            &initiator_kem_pk,
            responder_kp.public_key.clone(),
            &responder_kp.secret_key,
        )
        .unwrap();

        // Steps 5-6: Initiator decapsulates + verifies responder + signs
        // SEC-004 fix: pass expected responder pk for MITM protection
        let initiator_result = hs
            .complete_verified(&reply, &initiator_kp.secret_key, &responder_kp.public_key)
            .unwrap();

        // Step 7: Responder verifies initiator's signature (MUTUAL AUTH)
        let responder_result = reply
            .verify_initiator(&initiator_result.our_signature, &initiator_kp.public_key)
            .unwrap();

        // Both sides have the same session key
        assert_eq!(initiator_result.session_key, responder_result.session_key);
        // Initiator knows responder's identity
        assert_eq!(initiator_result.peer_pk, responder_kp.public_key);
        // Responder knows initiator's identity
        assert_eq!(responder_result.peer_pk, initiator_kp.public_key);
    }

    #[test]
    fn test_mutual_auth_wrong_initiator_rejected() {
        let initiator_kp = generate_validator_keypair();
        let responder_kp = generate_validator_keypair();
        let imposter_kp = generate_validator_keypair();

        let hs = InitiatorHandshake::new(initiator_kp.public_key.clone()).unwrap();
        let initiator_kem_pk = hs.ephemeral_pk.clone();

        let reply = responder_handle(
            &initiator_kem_pk,
            responder_kp.public_key.clone(),
            &responder_kp.secret_key,
        )
        .unwrap();

        let initiator_result = hs
            .complete_verified(&reply, &initiator_kp.secret_key, &responder_kp.public_key)
            .unwrap();

        // Responder tries to verify with wrong public key (imposter)
        let result =
            reply.verify_initiator(&initiator_result.our_signature, &imposter_kp.public_key);
        assert!(result.is_err(), "imposter initiator must be rejected");
    }

    #[test]
    fn test_mutual_auth_wrong_responder_rejected() {
        let initiator_kp = generate_validator_keypair();
        let responder_kp = generate_validator_keypair();
        let imposter_kp = generate_validator_keypair();

        let hs = InitiatorHandshake::new(initiator_kp.public_key.clone()).unwrap();
        let initiator_kem_pk = hs.ephemeral_pk.clone();

        // Imposter pretends to be responder
        let reply = responder_handle(
            &initiator_kem_pk,
            imposter_kp.public_key.clone(),
            &imposter_kp.secret_key,
        )
        .unwrap();

        // SEC-004 fix: Initiator expects responder_kp but gets imposter → REJECTED
        let result =
            hs.complete_verified(&reply, &initiator_kp.secret_key, &responder_kp.public_key);
        assert!(
            result.is_err(),
            "imposter responder must be rejected when expected_pk is provided"
        );
    }
}
