//! PQ KEM output extension (§6 of spec).
//!
//! Phase 2c-B: deprecated. Retained for deserialization compatibility.
//! Minimal extension formerly attached to transaction outputs
//! for ML-KEM-768 based addressing.

use crate::error::MisakaError;
use crate::mcs1;

/// Version tag for the pq_kem protocol.
pub const PQ_STEALTH_VERSION: u8 = 0x01;

/// On-chain pq_kem extension data attached to an output.
///
/// Contains everything a recipient needs to try recovery:
/// - KEM ciphertext for shared-secret derivation
/// - Scan tag for cheap rejection
/// - AEAD-encrypted amount and payload
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
         borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct PqStealthData {
    /// Protocol version (currently 0x01).
    pub version: u8,
    /// ML-KEM-768 ciphertext (1088 bytes).
    pub kem_ct: Vec<u8>,
    /// Fast-rejection scan tag (16 bytes, HKDF-derived).
    pub scan_tag: [u8; 16],
    /// AEAD-encrypted amount (8-byte u64 LE + 16-byte Poly1305 tag).
    pub amount_ct: Vec<u8>,
    /// AEAD-encrypted payload (variable length + 16-byte Poly1305 tag).
    pub payload_ct: Vec<u8>,
}

impl PqStealthData {
    /// MCS-1 encode for on-chain serialization.
    pub fn mcs1_encode(&self, buf: &mut Vec<u8>) {
        mcs1::write_u8(buf, self.version);
        mcs1::write_bytes(buf, &self.kem_ct);
        buf.extend_from_slice(&self.scan_tag);
        mcs1::write_bytes(buf, &self.amount_ct);
        mcs1::write_bytes(buf, &self.payload_ct);
    }

    /// MCS-1 decode.
    pub fn mcs1_decode(data: &[u8], offset: &mut usize) -> Result<Self, MisakaError> {
        let version = mcs1::read_u8(data, offset)?;
        if version != PQ_STEALTH_VERSION {
            return Err(MisakaError::DeserializationError(format!(
                "unsupported pq_kem version: 0x{:02x}",
                version
            )));
        }
        let kem_ct = mcs1::read_bytes(data, offset)?;
        if kem_ct.len() != 1088 {
            return Err(MisakaError::DeserializationError(format!(
                "invalid kem_ct length: {} (expected 1088)",
                kem_ct.len()
            )));
        }
        let tag_bytes = mcs1::read_fixed(data, offset, 16)?;
        let mut scan_tag = [0u8; 16];
        scan_tag.copy_from_slice(&tag_bytes);
        let amount_ct = mcs1::read_bytes(data, offset)?;
        let payload_ct = mcs1::read_bytes(data, offset)?;

        Ok(Self {
            version,
            kem_ct,
            scan_tag,
            amount_ct,
            payload_ct,
        })
    }

    /// Wire size in bytes.
    pub fn wire_len(&self) -> usize {
        1 + 4 + self.kem_ct.len() + 16 + 4 + self.amount_ct.len() + 4 + self.payload_ct.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pq_kem_data_roundtrip() {
        let sd = PqStealthData {
            version: PQ_STEALTH_VERSION,
            kem_ct: vec![0xAA; 1088],
            scan_tag: [0xBB; 16],
            amount_ct: vec![0xCC; 24], // 8 + 16 (poly1305 tag)
            payload_ct: vec![0xDD; 32],
        };
        let mut buf = Vec::new();
        sd.mcs1_encode(&mut buf);
        let mut offset = 0;
        let sd2 = PqStealthData::mcs1_decode(&buf, &mut offset).unwrap();
        assert_eq!(sd, sd2);
        assert_eq!(offset, buf.len());
    }

    #[test]
    fn test_pq_kem_data_bad_version() {
        let mut buf = Vec::new();
        mcs1::write_u8(&mut buf, 0xFF);
        let mut offset = 0;
        assert!(PqStealthData::mcs1_decode(&buf, &mut offset).is_err());
    }
}
