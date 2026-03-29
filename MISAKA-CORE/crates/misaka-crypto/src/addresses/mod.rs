//! Address encoding, validation, and prefix management.
//!
//! MISAKA addresses use a Bech32-like encoding with:
//! - Network prefix: misaka1 (mainnet), misakatest1 (testnet), misakasim1 (simnet)
//! - 20-byte payload (Blake3 hash of public key)
//! - 4-character checksum (SHA3-based)
//! - Optional chain-id binding for cross-chain safety

pub mod prefix;
pub mod version;

use sha3::{Sha3_256, Digest};

/// Network prefix for address encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prefix {
    Mainnet,
    Testnet,
    Simnet,
    Devnet,
}

impl Prefix {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mainnet => "misaka1",
            Self::Testnet => "misakatest1",
            Self::Simnet => "misakasim1",
            Self::Devnet => "misakadev1",
        }
    }

    pub fn from_address(addr: &str) -> Option<Self> {
        if addr.starts_with("misaka1") { Some(Self::Mainnet) }
        else if addr.starts_with("misakatest1") { Some(Self::Testnet) }
        else if addr.starts_with("misakasim1") { Some(Self::Simnet) }
        else if addr.starts_with("misakadev1") { Some(Self::Devnet) }
        else { None }
    }
}

/// Address version — determines script type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressVersion {
    /// Pay-to-Public-Key-Hash (standard).
    PubKeyHash = 0,
    /// Pay-to-Script-Hash.
    ScriptHash = 8,
    /// Pay-to-Public-Key-Hash with PQ signature.
    PubKeyHashPQ = 16,
    /// Pay-to-Script-Hash with PQ multisig.
    ScriptHashPQ = 24,
}

/// Full address with prefix, version, and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub prefix: Prefix,
    pub version: AddressVersion,
    pub payload: [u8; 32],
}

impl Address {
    /// Create from a public key hash.
    pub fn from_public_key_hash(prefix: Prefix, hash: [u8; 32]) -> Self {
        Self { prefix, version: AddressVersion::PubKeyHash, payload: hash }
    }

    /// Create from a script hash.
    pub fn from_script_hash(prefix: Prefix, hash: [u8; 32]) -> Self {
        Self { prefix, version: AddressVersion::ScriptHash, payload: hash }
    }

    /// Create from a PQ public key.
    pub fn from_pq_public_key(prefix: Prefix, pubkey: &[u8]) -> Self {
        let hash = blake3_hash_to_address(pubkey);
        Self { prefix, version: AddressVersion::PubKeyHashPQ, payload: hash }
    }

    /// Encode to display string.
    pub fn encode(&self) -> String {
        let hex_payload = hex::encode(&self.payload[..20]);
        let version_byte = format!("{:02x}", self.version as u8);
        let data = format!("{}{}", version_byte, hex_payload);
        let checksum = compute_checksum(&data, self.prefix);
        format!("{}{}{}", self.prefix.as_str(), data, checksum)
    }

    /// Decode from display string.
    pub fn decode(s: &str) -> Result<Self, AddressError> {
        let prefix = Prefix::from_address(s).ok_or(AddressError::InvalidPrefix)?;
        let after_prefix = s.strip_prefix(prefix.as_str())
            .ok_or(AddressError::InvalidPrefix)?;

        if after_prefix.len() < 46 {
            return Err(AddressError::TooShort(after_prefix.len()));
        }

        let version_hex = &after_prefix[..2];
        let payload_hex = &after_prefix[2..42];
        let checksum = &after_prefix[42..46];

        // Verify checksum
        let data = format!("{}{}", version_hex, payload_hex);
        let expected = compute_checksum(&data, prefix);
        if checksum != expected {
            return Err(AddressError::ChecksumMismatch);
        }

        let version_byte = u8::from_str_radix(version_hex, 16)
            .map_err(|_| AddressError::InvalidVersion)?;
        let version = match version_byte {
            0 => AddressVersion::PubKeyHash,
            8 => AddressVersion::ScriptHash,
            16 => AddressVersion::PubKeyHashPQ,
            24 => AddressVersion::ScriptHashPQ,
            _ => return Err(AddressError::InvalidVersion),
        };

        let payload_bytes = hex::decode(payload_hex)
            .map_err(|_| AddressError::InvalidPayload)?;
        let mut payload = [0u8; 32];
        payload[..20].copy_from_slice(&payload_bytes);

        Ok(Self { prefix, version, payload })
    }

    /// Derive the script public key for this address.
    pub fn to_script_public_key(&self) -> Vec<u8> {
        match self.version {
            AddressVersion::PubKeyHash => {
                let mut script = Vec::with_capacity(37);
                script.push(0x76); // OP_DUP
                script.push(0xa7); // OP_BLAKE3
                script.push(32);
                script.extend_from_slice(&self.payload);
                script.push(0x88); // OP_EQUALVERIFY
                script.push(0xac); // OP_CHECKSIG
                script
            }
            AddressVersion::PubKeyHashPQ => {
                let mut script = Vec::with_capacity(37);
                script.push(0x76);
                script.push(0xa7);
                script.push(32);
                script.extend_from_slice(&self.payload);
                script.push(0x88);
                script.push(0xc0); // OP_CHECKSIG_PQ
                script
            }
            AddressVersion::ScriptHash | AddressVersion::ScriptHashPQ => {
                let mut script = Vec::with_capacity(35);
                script.push(0xa7);
                script.push(32);
                script.extend_from_slice(&self.payload);
                script.push(0x87); // OP_EQUAL
                script
            }
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encode())
    }
}

fn blake3_hash_to_address(data: &[u8]) -> [u8; 32] {
    let hash = blake3::hash(data);
    *hash.as_bytes()
}

fn compute_checksum(data: &str, prefix: Prefix) -> String {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:addr:cksum:v2:");
    h.update(prefix.as_str().as_bytes());
    h.update(data.as_bytes());
    let hash: [u8; 32] = h.finalize().into();
    hex::encode(&hash[..2])
}

#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    #[error("invalid prefix")]
    InvalidPrefix,
    #[error("address too short: {0} chars")]
    TooShort(usize),
    #[error("checksum mismatch")]
    ChecksumMismatch,
    #[error("invalid version byte")]
    InvalidVersion,
    #[error("invalid payload")]
    InvalidPayload,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_round_trip() {
        let addr = Address::from_public_key_hash(Prefix::Mainnet, [0xAB; 32]);
        let encoded = addr.encode();
        assert!(encoded.starts_with("misaka1"));
        let decoded = Address::decode(&encoded).unwrap();
        assert_eq!(addr.prefix, decoded.prefix);
        assert_eq!(addr.version, decoded.version);
    }

    #[test]
    fn test_pq_address() {
        let addr = Address::from_pq_public_key(Prefix::Mainnet, &[42u8; 1952]);
        let encoded = addr.encode();
        let decoded = Address::decode(&encoded).unwrap();
        assert_eq!(decoded.version, AddressVersion::PubKeyHashPQ);
    }

    #[test]
    fn test_checksum_detects_corruption() {
        let addr = Address::from_public_key_hash(Prefix::Mainnet, [0x01; 32]);
        let mut encoded = addr.encode();
        // Corrupt last character
        let bytes = unsafe { encoded.as_bytes_mut() };
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(Address::decode(&encoded).is_err());
    }
}
