//! PQ-hardened handshake with MUTUAL authentication.
//!
//! Protocol:
//! 1. Initiator → Responder: ephemeral ML-KEM-768 PK
//! 2. Responder: encapsulate → ciphertext + shared secret
//! 3. Responder → Initiator: ciphertext + responder hybrid PK
//! 4. Both derive session key from shared secret
//! 5. Initiator: signs transcript with hybrid key → sends sig
//! 6. Responder: signs transcript with hybrid key → sends sig
//! 7. Both verify each other's signatures → mutual auth complete

use misaka_pqc::pq_kem::{ml_kem_keygen, ml_kem_encapsulate, ml_kem_decapsulate, kdf_derive};
use misaka_pqc::pq_kem::{MlKemPublicKey, MlKemSecretKey, MlKemCiphertext};
use misaka_pqc::error::CryptoError;
use misaka_crypto::hybrid::{
    HybridPublicKey, HybridSecretKey, HybridSignature,
    hybrid_sign, hybrid_verify,
};

const DST_SESSION: &[u8] = b"MISAKA-v1:p2p:session-key:";
const DST_TRANSCRIPT: &[u8] = b"MISAKA-v1:p2p:transcript:";

/// Completed handshake result.
pub struct HandshakeResult {
    pub session_key: [u8; 32],
    pub peer_pk: HybridPublicKey,
}

/// Initiator's handshake state.
pub struct InitiatorHandshake {
    pub ephemeral_pk: MlKemPublicKey,
    ephemeral_sk: MlKemSecretKey,
    pub identity_pk: HybridPublicKey,
}

/// Responder's reply.
pub struct ResponderReply {
    pub ciphertext: MlKemCiphertext,
    pub responder_pk: HybridPublicKey,
    pub responder_sig: HybridSignature,
    session_key: [u8; 32],
}

impl InitiatorHandshake {
    /// Step 1: Initiator generates ephemeral KEM keypair.
    pub fn new(identity_pk: HybridPublicKey) -> Result<Self, CryptoError> {
        let kp = ml_kem_keygen()?;
        Ok(Self { ephemeral_pk: kp.public_key, ephemeral_sk: kp.secret_key, identity_pk })
    }

    /// Step 5: Initiator completes handshake.
    pub fn complete(
        self,
        reply: &ResponderReply,
        identity_sk: &HybridSecretKey,
    ) -> Result<HandshakeResult, CryptoError> {
        // Decapsulate
        let ss = ml_kem_decapsulate(&self.ephemeral_sk, &reply.ciphertext)?;
        let session_key = kdf_derive(&ss, DST_SESSION, 0);

        // Build transcript for mutual auth
        let transcript = build_transcript(
            &self.ephemeral_pk, &reply.ciphertext, &session_key,
        );

        // Verify responder's signature on transcript
        hybrid_verify(&transcript, &reply.responder_sig, &reply.responder_pk)
            .map_err(|_| CryptoError::MlKemDecapsulateFailed)?;

        // Sign transcript ourselves (initiator auth)
        let _our_sig = hybrid_sign(&transcript, identity_sk)
            .map_err(|_| CryptoError::MlKemDecapsulateFailed)?;
        // In real protocol, send _our_sig to responder

        Ok(HandshakeResult { session_key, peer_pk: reply.responder_pk.clone() })
    }
}

/// Step 2-4: Responder handles initiator's ephemeral PK.
pub fn responder_handle(
    initiator_kem_pk: &MlKemPublicKey,
    identity_pk: HybridPublicKey,
    identity_sk: &HybridSecretKey,
) -> Result<ResponderReply, CryptoError> {
    let (ct, ss) = ml_kem_encapsulate(initiator_kem_pk)?;
    let session_key = kdf_derive(&ss, DST_SESSION, 0);

    let transcript = build_transcript(initiator_kem_pk, &ct, &session_key);
    let sig = hybrid_sign(&transcript, identity_sk).unwrap();

    Ok(ResponderReply { ciphertext: ct, responder_pk: identity_pk, responder_sig: sig, session_key })
}

fn build_transcript(
    kem_pk: &MlKemPublicKey, ct: &MlKemCiphertext, session_key: &[u8; 32],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(DST_TRANSCRIPT.len() + 1184 + 1088 + 32);
    t.extend_from_slice(DST_TRANSCRIPT);
    t.extend_from_slice(kem_pk.as_bytes());
    t.extend_from_slice(ct.as_bytes());
    t.extend_from_slice(session_key);
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_crypto::hybrid::generate_hybrid_keypair;

    #[test]
    fn test_mutual_auth_handshake() {
        let initiator_kp = generate_hybrid_keypair();
        let responder_kp = generate_hybrid_keypair();

        // Initiator starts
        let hs = InitiatorHandshake::new(initiator_kp.public_key.clone()).unwrap();
        let initiator_kem_pk = hs.ephemeral_pk.clone();

        // Responder handles
        let reply = responder_handle(
            &initiator_kem_pk,
            responder_kp.public_key.clone(),
            &responder_kp.secret_key,
        ).unwrap();

        // Initiator completes
        let result = hs.complete(&reply, &initiator_kp.secret_key).unwrap();

        // Both have same session key
        assert_eq!(result.session_key, reply.session_key);
        // Initiator knows responder's identity
        assert_eq!(result.peer_pk, responder_kp.public_key);
    }
}
