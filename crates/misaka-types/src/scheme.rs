//! Cryptographic signature scheme abstraction — PQ-only.
//!
//! MISAKA Network uses exclusively post-quantum cryptography:
//! - **ML-DSA-65** (FIPS 204): Required for all signatures
//! - **LaRRS**: Reserved for future ML-DSA signature extensions
//!
//! No ECC (Ed25519, ECDSA, etc.) is used anywhere.

use crate::error::MisakaError;
use crate::mcs1;
use crate::Address;
use serde::{Deserialize, Serialize};
use sha3::{Digest as Sha3Digest, Sha3_256};

/// Signature scheme identifier (1 byte on-wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SignatureScheme {
    /// ML-DSA-65 (FIPS 204 / Dilithium3). pk=1952, sig=3309.
    MlDsa65 = 0x01,
    /// Lattice ML-DSA signature (MISAKA-LRS-v1). Variable size.
    LatticeRing = 0x02,
}

impl SignatureScheme {
    pub fn from_u8(v: u8) -> Result<Self, MisakaError> {
        match v {
            0x01 => Ok(Self::MlDsa65),
            0x02 => Ok(Self::LatticeRing),
            _ => Err(MisakaError::UnknownSignatureScheme(v)),
        }
    }

    pub fn pk_size(&self) -> usize {
        match self {
            Self::MlDsa65 => 1952,
            Self::LatticeRing => 512, // lattice public poly (256 * 2 bytes)
        }
    }

    pub fn max_sig_size(&self) -> usize {
        match self {
            Self::MlDsa65 => 3309,
            Self::LatticeRing => 0, // variable (ring-size dependent)
        }
    }
}

/// Scheme-tagged public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MisakaPublicKey {
    pub scheme: SignatureScheme,
    pub bytes: Vec<u8>,
}

impl MisakaPublicKey {
    /// Create an ML-DSA-65 public key.
    pub fn ml_dsa(bytes: Vec<u8>) -> Result<Self, MisakaError> {
        if bytes.len() != 1952 {
            return Err(MisakaError::InvalidPublicKeyLength {
                expected: 1952,
                got: bytes.len(),
            });
        }
        Ok(Self {
            scheme: SignatureScheme::MlDsa65,
            bytes,
        })
    }

    /// Derive MISAKA address: SHA3-256(scheme_tag || pk_bytes)[0..20]
    pub fn to_address(&self) -> Address {
        let mut hasher = Sha3_256::new();
        hasher.update([self.scheme as u8]);
        hasher.update(&self.bytes);
        let hash: [u8; 32] = hasher.finalize().into();
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&hash);
        addr
    }

    pub fn mcs1_encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.scheme as u8);
        mcs1::write_u32(buf, self.bytes.len() as u32);
        buf.extend_from_slice(&self.bytes);
    }

    pub fn mcs1_decode(data: &[u8], offset: &mut usize) -> Result<Self, MisakaError> {
        if *offset >= data.len() {
            return Err(MisakaError::DeserializationError(
                "EOF reading pk scheme".into(),
            ));
        }
        let scheme = SignatureScheme::from_u8(data[*offset])?;
        *offset += 1;
        let len = mcs1::read_u32(data, offset)? as usize;
        if *offset + len > data.len() {
            return Err(MisakaError::DeserializationError(
                "EOF reading pk bytes".into(),
            ));
        }
        let bytes = data[*offset..*offset + len].to_vec();
        *offset += len;
        Ok(Self { scheme, bytes })
    }

    pub fn wire_len(&self) -> usize {
        1 + 4 + self.bytes.len()
    }
}

/// Scheme-tagged signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MisakaSignature {
    pub scheme: SignatureScheme,
    pub bytes: Vec<u8>,
}

impl MisakaSignature {
    pub fn ml_dsa(bytes: Vec<u8>) -> Self {
        Self {
            scheme: SignatureScheme::MlDsa65,
            bytes,
        }
    }

    pub fn mcs1_encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.scheme as u8);
        mcs1::write_u32(buf, self.bytes.len() as u32);
        buf.extend_from_slice(&self.bytes);
    }

    pub fn mcs1_decode(data: &[u8], offset: &mut usize) -> Result<Self, MisakaError> {
        if *offset >= data.len() {
            return Err(MisakaError::DeserializationError(
                "EOF reading sig scheme".into(),
            ));
        }
        let scheme = SignatureScheme::from_u8(data[*offset])?;
        *offset += 1;
        let len = mcs1::read_u32(data, offset)? as usize;
        if *offset + len > data.len() {
            return Err(MisakaError::DeserializationError(
                "EOF reading sig bytes".into(),
            ));
        }
        let bytes = data[*offset..*offset + len].to_vec();
        *offset += len;
        Ok(Self { scheme, bytes })
    }

    pub fn wire_len(&self) -> usize {
        1 + 4 + self.bytes.len()
    }
}

/// Secret key (NEVER serialized on-chain). Zeroized on drop.
#[derive(Clone)]
pub struct MisakaSecretKey {
    pub scheme: SignatureScheme,
    pub bytes: Vec<u8>,
}

impl MisakaSecretKey {
    pub fn ml_dsa(bytes: Vec<u8>) -> Self {
        Self {
            scheme: SignatureScheme::MlDsa65,
            bytes,
        }
    }
}

impl Drop for MisakaSecretKey {
    fn drop(&mut self) {
        // SEC-AUDIT-V5 MED-001: use zeroize crate to prevent compiler elision.
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for MisakaSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MisakaSk({:?}, [REDACTED])", self.scheme)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_address_derivation() {
        let pk = MisakaPublicKey::ml_dsa(vec![0xAA; 1952]).unwrap();
        let addr = pk.to_address();
        assert_eq!(addr.len(), 32);
        assert_eq!(pk.to_address(), pk.to_address()); // deterministic
    }

    #[test]
    fn test_pk_length_validation() {
        assert!(MisakaPublicKey::ml_dsa(vec![0; 1951]).is_err());
        assert!(MisakaPublicKey::ml_dsa(vec![0; 1952]).is_ok());
        assert!(MisakaPublicKey::ml_dsa(vec![0; 1953]).is_err());
    }

    #[test]
    fn test_pk_mcs1_roundtrip() {
        let pk = MisakaPublicKey::ml_dsa(vec![0x42; 1952]).unwrap();
        let mut buf = Vec::new();
        pk.mcs1_encode(&mut buf);
        let mut offset = 0;
        let pk2 = MisakaPublicKey::mcs1_decode(&buf, &mut offset).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_sig_mcs1_roundtrip() {
        let sig = MisakaSignature::ml_dsa(vec![0xDE; 3309]);
        let mut buf = Vec::new();
        sig.mcs1_encode(&mut buf);
        let mut offset = 0;
        let sig2 = MisakaSignature::mcs1_decode(&buf, &mut offset).unwrap();
        assert_eq!(sig, sig2);
    }

    #[test]
    fn test_scheme_from_u8() {
        assert_eq!(
            SignatureScheme::from_u8(0x01).unwrap(),
            SignatureScheme::MlDsa65
        );
        assert_eq!(
            SignatureScheme::from_u8(0x02).unwrap(),
            SignatureScheme::LatticeRing
        );
        assert!(SignatureScheme::from_u8(0xFF).is_err());
    }
}
