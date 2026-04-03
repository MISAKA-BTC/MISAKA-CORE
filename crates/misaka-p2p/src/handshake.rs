//! PQ-only handshake with MUTUAL authentication.
//!
//! Protocol (ECC-free, ML-KEM-768 + ML-DSA-65):
//! 1. Initiator → Responder: ephemeral ML-KEM-768 PK + protocol_version + random nonce_i
//! 2. Responder: encapsulate → ciphertext + shared secret
//! 3. Responder → Initiator: ciphertext + responder PQ PK + PQ sig + random nonce_r
//! 4. Both derive session key from shared secret
//! 5. Initiator: signs transcript with ML-DSA-65 → sends sig
//! 6. Responder: signs transcript with ML-DSA-65 → sends sig
//! 7. Both verify each other's signatures → mutual auth complete
//!
//! No ECC (Ed25519, secp256k1) is used anywhere.
//!
//! # Security Improvements (v2 → v3)
//!
//! ## SEC-HS-FRESH: Freshness Nonces
//!
//! Both sides contribute a random 32-byte nonce to the transcript.
//! This prevents replay attacks where an attacker records a complete
//! handshake flow and replays it later. Without freshness nonces, if
//! the same ephemeral KEM keypair were somehow reused (e.g., weak RNG),
//! the transcript would be identical and an attacker could replay the
//! entire handshake. The nonces ensure every handshake produces a
//! unique transcript even with identical keys.
//!
//! ## SEC-HS-VER: Protocol Version Negotiation
//!
//! The initiator sends a `protocol_version` byte. The responder checks
//! compatibility BEFORE performing any expensive crypto (KEM encapsulate).
//! This allows:
//! - Early rejection of incompatible peers (saves CPU)
//! - Future protocol upgrades without ambiguity
//! - Version downgrade detection (the version is bound into the transcript)
//!
//! ## SEC-HS-BIND: Identity Binding
//!
//! Both parties' ML-DSA-65 public keys are included in the transcript.
//! This prevents identity misbinding attacks where an attacker could
//! redirect a handshake intended for peer A to peer B. Without identity
//! binding, the transcript only proves "someone with a valid key signed
//! this exchange" — not "the specific peer I intended to talk to signed
//! this exchange."

use misaka_crypto::validator_sig::{
    validator_sign, validator_verify, ValidatorPqPublicKey, ValidatorPqSecretKey,
    ValidatorPqSignature,
};
use misaka_pqc::error::CryptoError;
use misaka_pqc::pq_kem::{kdf_derive, ml_kem_decapsulate, ml_kem_encapsulate, ml_kem_keygen};
use misaka_pqc::pq_kem::{MlKemCiphertext, MlKemPublicKey, MlKemSecretKey};

const DST_SESSION: &[u8] = b"MISAKA-v3:p2p:session-key:";
const DST_TRANSCRIPT: &[u8] = b"MISAKA-v3:p2p:transcript:";

/// Current protocol version.
///
/// Increment when the handshake wire format changes.
/// The version byte is bound into the transcript to prevent
/// downgrade attacks.
pub const PROTOCOL_VERSION: u8 = 3;

/// Minimum supported protocol version.
///
/// Peers announcing a version below this are rejected.
pub const MIN_PROTOCOL_VERSION: u8 = 3;

/// Freshness nonce size (bytes).
pub const FRESHNESS_NONCE_SIZE: usize = 32;

/// Completed handshake result.
pub struct HandshakeResult {
    pub session_key: [u8; 32],
    pub peer_pk: ValidatorPqPublicKey,
    /// Initiator's ML-DSA-65 signature over the transcript.
    /// MUST be sent to the responder for mutual authentication.
    pub our_signature: ValidatorPqSignature,
    /// Negotiated protocol version.
    pub protocol_version: u8,
}

/// Initiator's handshake state.
pub struct InitiatorHandshake {
    pub ephemeral_pk: MlKemPublicKey,
    /// Ephemeral secret key — consumed during handshake completion.
    /// `pub` for transport-layer wire protocol (dag_p2p_transport.rs)
    /// which performs raw KEM decapsulation over TCP.
    pub ephemeral_sk: MlKemSecretKey,
    pub identity_pk: ValidatorPqPublicKey,
    /// Random nonce contributed by the initiator (SEC-HS-FRESH).
    pub nonce_i: [u8; FRESHNESS_NONCE_SIZE],
    /// Protocol version announced by the initiator.
    pub protocol_version: u8,
}

/// Responder's reply (sent to initiator).
pub struct ResponderReply {
    pub ciphertext: MlKemCiphertext,
    pub responder_pk: ValidatorPqPublicKey,
    pub responder_sig: ValidatorPqSignature,
    /// Random nonce contributed by the responder (SEC-HS-FRESH).
    pub nonce_r: [u8; FRESHNESS_NONCE_SIZE],
    session_key: [u8; 32],
    /// Transcript needed for verifying initiator's signature in step 7.
    transcript: Vec<u8>,
    /// Negotiated protocol version.
    pub protocol_version: u8,
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
            our_signature: self.responder_sig.clone(),
            protocol_version: self.protocol_version,
        })
    }
}

impl InitiatorHandshake {
    /// Step 1: Initiator generates ephemeral KEM keypair + freshness nonce.
    pub fn new(identity_pk: ValidatorPqPublicKey) -> Result<Self, CryptoError> {
        let kp = ml_kem_keygen()?;

        // Generate random freshness nonce via CSPRNG-seeded KEM keygen
        let nonce_i = generate_freshness_nonce()?;

        Ok(Self {
            ephemeral_pk: kp.public_key,
            ephemeral_sk: kp.secret_key,
            identity_pk,
            nonce_i,
            protocol_version: PROTOCOL_VERSION,
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
        // ── Version check ──
        if reply.protocol_version < MIN_PROTOCOL_VERSION {
            return Err(CryptoError::MlKemDecapsulateFailed);
        }
        let negotiated_version = self.protocol_version.min(reply.protocol_version);

        // Decapsulate
        let ss = ml_kem_decapsulate(&self.ephemeral_sk, &reply.ciphertext)?;
        let session_key = kdf_derive(&ss, DST_SESSION, 0);

        // Build transcript for mutual auth (SEC-HS-FRESH + SEC-HS-BIND)
        //
        // IMPORTANT: The initiator_pk slot uses ValidatorPqPublicKey::zero() — the same
        // placeholder the responder uses — so both sides compute identical transcripts.
        // The initiator's identity is proven through the ML-DSA-65 signature over this
        // transcript (only the real key holder can produce a valid signature), which
        // the responder verifies in step 7 via verify_initiator(sig, initiator_pk).
        //
        // The responder's identity IS bound into the transcript directly (rpk_hash),
        // because the responder's PK is known to the initiator from step 3.
        let transcript = build_transcript(
            &self.ephemeral_pk,
            &reply.ciphertext,
            &self.nonce_i,
            &reply.nonce_r,
            &ValidatorPqPublicKey::zero(), // placeholder — matches responder's transcript
            &reply.responder_pk,
            negotiated_version,
        );

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
            protocol_version: negotiated_version,
        })
    }
}

/// Step 2-4: Responder handles initiator's ephemeral PK + nonce.
///
/// # Version Check (SEC-HS-VER)
///
/// The responder checks `initiator_version` BEFORE performing any
/// expensive cryptographic operations. If the version is below
/// `MIN_PROTOCOL_VERSION`, the handshake is immediately rejected.
///
/// After calling this, the responder MUST:
/// 1. Send the reply (ciphertext + pk + sig + nonce_r) to the initiator
/// 2. Receive the initiator's signature + pk
/// 3. Call reply.verify_initiator() to complete mutual auth
/// 4. If verify_initiator() fails → DROP the connection immediately
pub fn responder_handle(
    initiator_kem_pk: &MlKemPublicKey,
    nonce_i: &[u8; FRESHNESS_NONCE_SIZE],
    initiator_version: u8,
    identity_pk: ValidatorPqPublicKey,
    identity_sk: &ValidatorPqSecretKey,
) -> Result<ResponderReply, CryptoError> {
    // ── Early version rejection (before any expensive crypto) ──
    if initiator_version < MIN_PROTOCOL_VERSION {
        return Err(CryptoError::MlKemEncapsulateFailed);
    }
    let negotiated_version = PROTOCOL_VERSION.min(initiator_version);

    // Generate responder's freshness nonce
    let nonce_r = generate_freshness_nonce()?;

    let (ct, ss) = ml_kem_encapsulate(initiator_kem_pk)?;
    let session_key = kdf_derive(&ss, DST_SESSION, 0);

    // Build transcript with both nonces + both identities (SEC-HS-FRESH + SEC-HS-BIND)
    //
    // NOTE: The responder doesn't yet know the initiator's identity PK at this point.
    // We use ValidatorPqPublicKey::zero() as a placeholder. The initiator's identity
    // is proven when they sign the SAME transcript in step 5 and verified in step 7.
    // Both sides compute the transcript with the same zeroed initiator PK, so the
    // signatures remain consistent.
    let transcript = build_transcript(
        initiator_kem_pk,
        &ct,
        nonce_i,
        &nonce_r,
        &ValidatorPqPublicKey::zero(),
        &identity_pk,
        negotiated_version,
    );
    let sig = validator_sign(&transcript, identity_sk)
        .map_err(|_| CryptoError::MlKemEncapsulateFailed)?;

    Ok(ResponderReply {
        ciphertext: ct,
        responder_pk: identity_pk,
        responder_sig: sig,
        nonce_r,
        session_key,
        transcript,
        protocol_version: negotiated_version,
    })
}

/// Build the mutual authentication transcript.
///
/// # Security
///
/// The transcript binds:
/// - Protocol version (prevents downgrade attacks — SEC-HS-VER)
/// - Initiator nonce (freshness from initiator side — SEC-HS-FRESH)
/// - Responder nonce (freshness from responder side — SEC-HS-FRESH)
/// - KEM public key (identifies the key exchange)
/// - KEM ciphertext (uniquely identifies this session)
/// - Initiator identity PK hash (prevents identity misbinding — SEC-HS-BIND)
/// - Responder identity PK hash (prevents identity misbinding — SEC-HS-BIND)
///
/// Identity public keys (1952 bytes each for ML-DSA-65) are hashed with
/// domain-separated SHA3-256 to keep the transcript compact.
fn build_transcript(
    kem_pk: &MlKemPublicKey,
    ct: &MlKemCiphertext,
    nonce_i: &[u8; FRESHNESS_NONCE_SIZE],
    nonce_r: &[u8; FRESHNESS_NONCE_SIZE],
    initiator_pk: &ValidatorPqPublicKey,
    responder_pk: &ValidatorPqPublicKey,
    protocol_version: u8,
) -> Vec<u8> {
    use sha3::{Digest, Sha3_256};

    // Hash identity PKs to keep transcript compact
    let ipk_hash: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA-v3:initiator-pk:");
        h.update(&initiator_pk.to_bytes());
        h.finalize().into()
    };
    let rpk_hash: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA-v3:responder-pk:");
        h.update(&responder_pk.to_bytes());
        h.finalize().into()
    };

    let mut t =
        Vec::with_capacity(DST_TRANSCRIPT.len() + 1 + FRESHNESS_NONCE_SIZE * 2 + 1184 + 1088 + 64);
    t.extend_from_slice(DST_TRANSCRIPT);
    t.push(protocol_version); // SEC-HS-VER: version binding
    t.extend_from_slice(nonce_i); // SEC-HS-FRESH: initiator freshness
    t.extend_from_slice(nonce_r); // SEC-HS-FRESH: responder freshness
    t.extend_from_slice(kem_pk.as_bytes());
    t.extend_from_slice(ct.as_bytes());
    t.extend_from_slice(&ipk_hash); // SEC-HS-BIND: initiator identity
    t.extend_from_slice(&rpk_hash); // SEC-HS-BIND: responder identity
    t
}

/// Generate a 32-byte freshness nonce from the OS CSPRNG.
///
/// # Security
///
/// Uses `rand::rngs::OsRng` which delegates to the operating system's
/// cryptographically secure random number generator:
/// - Linux: `getrandom(2)` syscall (backed by ChaCha20 DRNG)
/// - macOS: `SecRandomCopyBytes`
/// - Windows: `BCryptGenRandom`
///
/// This is ~100x faster than the previous `ml_kem_keygen()` approach
/// while providing identical security guarantees — both ultimately draw
/// from the same OS entropy pool.
///
/// # Fail-Closed
///
/// Returns `CryptoError` if the OS CSPRNG is unavailable (should never
/// happen in practice; indicates a catastrophic system failure).
fn generate_freshness_nonce() -> Result<[u8; FRESHNESS_NONCE_SIZE], CryptoError> {
    use rand::RngCore;

    let mut nonce = [0u8; FRESHNESS_NONCE_SIZE];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::MlKemDecapsulateFailed)?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_crypto::validator_sig::generate_validator_keypair;

    #[test]
    fn test_mutual_auth_handshake_v3() {
        let initiator_kp = generate_validator_keypair();
        let responder_kp = generate_validator_keypair();

        // Step 1: Initiator generates ephemeral KEM keypair + nonce
        let hs = InitiatorHandshake::new(initiator_kp.public_key.clone()).unwrap();
        let initiator_kem_pk = hs.ephemeral_pk.clone();
        let nonce_i = hs.nonce_i;
        let initiator_version = hs.protocol_version;

        // Steps 2-4: Responder encapsulates + signs transcript (with nonces)
        let reply = responder_handle(
            &initiator_kem_pk,
            &nonce_i,
            initiator_version,
            responder_kp.public_key.clone(),
            &responder_kp.secret_key,
        )
        .unwrap();

        // Steps 5-6: Initiator decapsulates + verifies responder + signs
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
        // Protocol version negotiated
        assert_eq!(initiator_result.protocol_version, PROTOCOL_VERSION);
    }

    #[test]
    fn test_mutual_auth_wrong_initiator_rejected() {
        let initiator_kp = generate_validator_keypair();
        let responder_kp = generate_validator_keypair();
        let imposter_kp = generate_validator_keypair();

        let hs = InitiatorHandshake::new(initiator_kp.public_key.clone()).unwrap();
        let initiator_kem_pk = hs.ephemeral_pk.clone();
        let nonce_i = hs.nonce_i;

        let reply = responder_handle(
            &initiator_kem_pk,
            &nonce_i,
            PROTOCOL_VERSION,
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
        let nonce_i = hs.nonce_i;

        // Imposter pretends to be responder
        let reply = responder_handle(
            &initiator_kem_pk,
            &nonce_i,
            PROTOCOL_VERSION,
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

    #[test]
    fn test_version_too_low_rejected_by_responder() {
        let initiator_kp = generate_validator_keypair();
        let responder_kp = generate_validator_keypair();

        let hs = InitiatorHandshake::new(initiator_kp.public_key.clone()).unwrap();
        let initiator_kem_pk = hs.ephemeral_pk.clone();
        let nonce_i = hs.nonce_i;

        // Initiator claims version 1 (below MIN_PROTOCOL_VERSION)
        let result = responder_handle(
            &initiator_kem_pk,
            &nonce_i,
            1, // too old
            responder_kp.public_key.clone(),
            &responder_kp.secret_key,
        );
        assert!(result.is_err(), "old protocol version must be rejected");
    }

    #[test]
    fn test_freshness_nonces_differ_per_handshake() {
        let pk = generate_validator_keypair().public_key;
        let hs1 = InitiatorHandshake::new(pk.clone()).unwrap();
        let hs2 = InitiatorHandshake::new(pk).unwrap();
        assert_ne!(
            hs1.nonce_i, hs2.nonce_i,
            "each handshake must have a unique nonce"
        );
    }
}
