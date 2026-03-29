//! Signature compression via coefficient packing.
//!
//! Dilithium-style high-bits/low-bits decomposition for response
//! polynomials. Since ||z||_∞ < β = 5954 < 2^13, each coefficient
//! fits in 14 bits instead of 16 bits (2 bytes).
//!
//! Savings: 256 coefficients × 2 bits = 64 bytes per polynomial.
//! For ring=4: 4 × 64 = 256 bytes saved (~16% reduction).

use super::error::CryptoError;
use super::pq_ring::{Poly, LegacyProofData, BETA, N, Q};

/// Bits needed per coefficient: ceil(log2(2*BETA)) = 13 bits.
const COEFF_BITS: usize = 14;

/// Pack a response polynomial (coefficients in [0, q), bounded by β).
///
/// Each coefficient is stored as a signed 13-bit value in centered
/// form [-β+1, β-1], then offset to unsigned [0, 2β-2].
pub fn pack_response(z: &Poly) -> Vec<u8> {
    let mut bits = Vec::with_capacity(N * COEFF_BITS);
    for i in 0..N {
        // Center: if c > q/2, c -= q
        let c = z.coeffs[i];
        let centered = if c > Q / 2 { c - Q } else { c };
        // Offset to unsigned: val = centered + (BETA - 1)
        let val = (centered + BETA - 1) as u16;
        // Push 13 bits, LSB first
        for bit in 0..COEFF_BITS {
            bits.push(((val >> bit) & 1) as u8);
        }
    }
    // Convert bits to bytes
    let mut bytes = vec![0u8; (bits.len() + 7) / 8];
    for (i, &b) in bits.iter().enumerate() {
        bytes[i / 8] |= b << (i % 8);
    }
    bytes
}

/// Unpack a response polynomial from packed bytes.
pub fn unpack_response(data: &[u8]) -> Result<Poly, CryptoError> {
    let expected_bits = N * COEFF_BITS;
    let expected_bytes = (expected_bits + 7) / 8;
    if data.len() != expected_bytes {
        return Err(CryptoError::ProofInvalid(format!(
            "packed response: {} bytes, expected {}",
            data.len(),
            expected_bytes
        )));
    }

    let mut p = Poly::zero();
    for i in 0..N {
        let bit_offset = i * COEFF_BITS;
        let mut val = 0u16;
        for bit in 0..COEFF_BITS {
            let byte_idx = (bit_offset + bit) / 8;
            let bit_idx = (bit_offset + bit) % 8;
            val |= (((data[byte_idx] >> bit_idx) & 1) as u16) << bit;
        }
        // Convert back: centered = val - (BETA - 1)
        let centered = val as i32 - (BETA - 1);
        p.coeffs[i] = ((centered % Q) + Q) % Q;
    }
    Ok(p)
}

/// Packed response size in bytes.
pub const PACKED_RESPONSE_SIZE: usize = (N * COEFF_BITS + 7) / 8; // 416 bytes

/// Pack an entire lattice ZKP proof (compressed format).
///
/// Format: challenge(256B) || packed_responses(416B each) || key_image(32B)
pub fn pack_ring_sig(sig: &LegacyProofData) -> Vec<u8> {
    let n = sig.responses.len();
    let mut buf = Vec::with_capacity(N + n * PACKED_RESPONSE_SIZE + 32);
    // Challenge polynomial (1 byte per coeff, only {-1,0,1})
    match sig.c0.challenge_to_bytes() {
        Ok(bytes) => buf.extend_from_slice(&bytes),
        Err(_) => buf.extend_from_slice(&vec![0u8; N]),
    }
    // Packed responses
    for z in &sig.responses {
        buf.extend_from_slice(&pack_response(z));
    }
    // Key image
    buf.extend_from_slice(&sig.key_image);
    buf
}

/// Unpack a compressed lattice ZKP proof.
pub fn unpack_legacy_proof(data: &[u8], anonymity_set_size: usize) -> Result<LegacyProofData, CryptoError> {
    let expected = N + anonymity_set_size * PACKED_RESPONSE_SIZE + 32;
    if data.len() != expected {
        return Err(CryptoError::ProofInvalid(format!(
            "packed sig: {} bytes, expected {}",
            data.len(),
            expected
        )));
    }

    let c0 = Poly::challenge_from_bytes(&data[..N])?;
    let mut responses = Vec::with_capacity(anonymity_set_size);
    let mut offset = N;
    for _ in 0..anonymity_set_size {
        responses.push(unpack_response(
            &data[offset..offset + PACKED_RESPONSE_SIZE],
        )?);
        offset += PACKED_RESPONSE_SIZE;
    }
    let mut ki = [0u8; 32];
    ki.copy_from_slice(&data[offset..]);

    Ok(LegacyProofData {
        c0,
        responses,
        key_image: ki,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_unpack_response_roundtrip() {
        let mut p = Poly::zero();
        // Set various values within β bound
        p.coeffs[0] = 0;
        p.coeffs[1] = 1;
        p.coeffs[2] = Q - 1; // -1
        p.coeffs[3] = 5000; // within β
        p.coeffs[4] = Q - 5000; // -5000, within β
        p.coeffs[100] = (BETA - 2) as i32;
        p.coeffs[200] = ((-(BETA - 2)) as i32 + Q) as i32;

        let packed = pack_response(&p);
        assert_eq!(packed.len(), PACKED_RESPONSE_SIZE);

        let unpacked = unpack_response(&packed).unwrap();
        for i in 0..N {
            // Compare centered values
            let a = if p.coeffs[i] > Q / 2 {
                p.coeffs[i] - Q
            } else {
                p.coeffs[i]
            };
            let b = if unpacked.coeffs[i] > Q / 2 {
                unpacked.coeffs[i] - Q
            } else {
                unpacked.coeffs[i]
            };
            assert_eq!(a, b, "mismatch at coefficient {i}: orig={a}, unpacked={b}");
        }
    }

    #[test]
    fn test_pack_ring_sig_roundtrip() {
        use crate::pq_ring::*;
        use crate::pq_sign::MlDsaKeypair;

        let a = derive_public_param(&DEFAULT_A_SEED);
        let kps: Vec<SpendingKeypair> = (0..4)
            .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap())
            .collect();
        let ring: Vec<Poly> = kps.iter().map(|k| k.public_poly.clone()).collect();
        let msg = [0x42u8; 32];

        let sig = pq_sign(&a, &ring, 1, &kps[1].secret_poly, &msg).unwrap();

        // Pack
        let packed = pack_ring_sig(&sig);
        let unpacked_size = sig.to_bytes().len();
        println!("  Unpacked: {} bytes", unpacked_size);
        println!("  Packed:   {} bytes", packed.len());
        println!(
            "  Savings:  {} bytes ({:.1}%)",
            unpacked_size - packed.len(),
            (1.0 - packed.len() as f64 / unpacked_size as f64) * 100.0
        );

        // Unpack and verify
        let sig2 = unpack_legacy_proof(&packed, 4).unwrap();
        ring_verify(&a, &ring, &msg, &sig2).expect("packed→unpacked sig must verify");
    }

    #[test]
    fn test_packed_sizes() {
        println!(
            "  PACKED_RESPONSE_SIZE: {} bytes (vs 512 unpacked)",
            PACKED_RESPONSE_SIZE
        );
        println!(
            "  Ring=4 packed sig: {} bytes",
            N + 4 * PACKED_RESPONSE_SIZE + 32
        );
        println!("  Ring=4 unpacked:   {} bytes", N + 4 * N * 2 + 32);
        println!(
            "  Ring=8 packed sig: {} bytes",
            N + 8 * PACKED_RESPONSE_SIZE + 32
        );
        println!("  Ring=8 unpacked:   {} bytes", N + 8 * N * 2 + 32);
    }
}

// ─── Compact Challenge Encoding ──────────────────────────────

/// Compact-encode a challenge polynomial.
///
/// Challenge c ∈ C_τ has exactly τ=46 non-zero coefficients (each ±1).
/// Instead of 256 bytes (1 per coeff), encode as:
///   - 1 byte: count of non-zero positions (τ)
///   - τ bytes: position indices (0..255)
///   - ceil(τ/8) bytes: sign bits (0=+1, 1=-1)
///
/// Size: 1 + 46 + 6 = 53 bytes (vs 256 bytes, 79% smaller).
pub fn pack_challenge(c: &Poly) -> Vec<u8> {
    let mut positions = Vec::new();
    let mut signs = Vec::new();
    for i in 0..N {
        if c.coeffs[i] == 1 {
            positions.push(i as u8);
            signs.push(0u8);
        } else if c.coeffs[i] == Q - 1 {
            positions.push(i as u8);
            signs.push(1u8);
        }
    }
    let count = positions.len() as u8;
    let sign_bytes = (positions.len() + 7) / 8;

    let mut buf = Vec::with_capacity(1 + positions.len() + sign_bytes);
    buf.push(count);
    buf.extend_from_slice(&positions);
    // Pack sign bits
    let mut sign_packed = vec![0u8; sign_bytes];
    for (i, &s) in signs.iter().enumerate() {
        sign_packed[i / 8] |= s << (i % 8);
    }
    buf.extend_from_slice(&sign_packed);
    buf
}

/// Unpack a compact-encoded challenge polynomial.
pub fn unpack_challenge(data: &[u8]) -> Result<(Poly, usize), CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::ProofInvalid(
            "empty challenge data".into(),
        ));
    }
    let count = data[0] as usize;
    let sign_bytes = (count + 7) / 8;
    let total = 1 + count + sign_bytes;
    if data.len() < total {
        return Err(CryptoError::ProofInvalid(
            "truncated challenge".into(),
        ));
    }

    let positions = &data[1..1 + count];
    let sign_data = &data[1 + count..total];

    let mut c = Poly::zero();
    for i in 0..count {
        let pos = positions[i] as usize;
        if pos >= N {
            return Err(CryptoError::ProofInvalid(
                "challenge position out of range".into(),
            ));
        }
        let sign_bit = (sign_data[i / 8] >> (i % 8)) & 1;
        c.coeffs[pos] = if sign_bit == 0 { 1 } else { Q - 1 };
    }

    Ok((c, total))
}

/// Packed challenge size for τ non-zero coefficients.
pub fn packed_challenge_size(tau: usize) -> usize {
    1 + tau + (tau + 7) / 8
}

// ─── V2 Compact Ring Signature ───────────────────────────────

/// Pack lattice ZKP proof v2 (compact challenge + 14-bit responses).
///
/// Format: compact_challenge || packed_responses(448B each) || key_image(32B)
pub fn pack_ring_sig_v2(sig: &LegacyProofData) -> Vec<u8> {
    let challenge_packed = pack_challenge(&sig.c0);
    let n = sig.responses.len();
    let mut buf = Vec::with_capacity(challenge_packed.len() + n * PACKED_RESPONSE_SIZE + 32);
    buf.extend_from_slice(&challenge_packed);
    for z in &sig.responses {
        buf.extend_from_slice(&pack_response(z));
    }
    buf.extend_from_slice(&sig.key_image);
    buf
}

/// Unpack lattice ZKP proof v2.
pub fn unpack_legacy_proof_v2(data: &[u8], anonymity_set_size: usize) -> Result<LegacyProofData, CryptoError> {
    // Decode challenge (variable length header)
    let (c0, c_len) = unpack_challenge(data)?;
    let remaining = &data[c_len..];
    let expected_remaining = anonymity_set_size * PACKED_RESPONSE_SIZE + 32;
    if remaining.len() != expected_remaining {
        return Err(CryptoError::ProofInvalid(format!(
            "v2 sig remaining: {} bytes, expected {}",
            remaining.len(),
            expected_remaining
        )));
    }

    let mut responses = Vec::with_capacity(anonymity_set_size);
    let mut offset = 0;
    for _ in 0..anonymity_set_size {
        responses.push(unpack_response(
            &remaining[offset..offset + PACKED_RESPONSE_SIZE],
        )?);
        offset += PACKED_RESPONSE_SIZE;
    }
    let mut ki = [0u8; 32];
    ki.copy_from_slice(&remaining[offset..]);

    Ok(LegacyProofData {
        c0,
        responses,
        key_image: ki,
    })
}

#[cfg(test)]
mod tests_v2 {
    use super::*;

    #[test]
    fn test_challenge_pack_unpack() {
        // Build a challenge with known positions
        let mut c = Poly::zero();
        c.coeffs[0] = 1;
        c.coeffs[10] = Q - 1;
        c.coeffs[255] = 1;

        let packed = pack_challenge(&c);
        let (unpacked, bytes_read) = unpack_challenge(&packed).unwrap();
        assert_eq!(bytes_read, packed.len());
        assert_eq!(c.coeffs, unpacked.coeffs);
    }

    #[test]
    fn test_v2_ring_sig_roundtrip() {
        use crate::pq_ring::*;
        use crate::pq_sign::MlDsaKeypair;

        let a = derive_public_param(&DEFAULT_A_SEED);
        let kps: Vec<SpendingKeypair> = (0..4)
            .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap())
            .collect();
        let ring: Vec<Poly> = kps.iter().map(|k| k.public_poly.clone()).collect();
        let msg = [0x42u8; 32];

        let sig = pq_sign(&a, &ring, 1, &kps[1].secret_poly, &msg).unwrap();

        let v1_size = sig.to_bytes().len();
        let v1_packed = pack_ring_sig(&sig).len();
        let v2_packed = pack_ring_sig_v2(&sig);

        println!("  v0 (raw):     {} bytes", v1_size);
        println!("  v1 (14-bit):  {} bytes", v1_packed);
        println!("  v2 (compact): {} bytes", v2_packed.len());
        println!(
            "  v0→v2 saving: {} bytes ({:.1}%)",
            v1_size - v2_packed.len(),
            (1.0 - v2_packed.len() as f64 / v1_size as f64) * 100.0
        );

        // Unpack and verify
        let sig2 = unpack_legacy_proof_v2(&v2_packed, 4).unwrap();
        ring_verify(&a, &ring, &msg, &sig2).expect("v2 unpacked sig must verify");
    }

    #[test]
    fn test_v2_sizes_comparison() {
        println!("\n  ═══ Size Comparison ═══");
        for ring in [4, 8, 16] {
            let v0 = N + ring * N * 2 + 32;
            let v1 = N + ring * PACKED_RESPONSE_SIZE + 32;
            let v2 = packed_challenge_size(46) + ring * PACKED_RESPONSE_SIZE + 32;
            println!(
                "  ring={:2}: v0={}B  v1={}B  v2={}B  (v0→v2: -{:.1}%)",
                ring,
                v0,
                v1,
                v2,
                (1.0 - v2 as f64 / v0 as f64) * 100.0
            );
        }
    }
}
