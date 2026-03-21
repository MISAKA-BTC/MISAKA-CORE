//! Object types per Spec 01 §5.

use crate::error::MisakaError;
use crate::mcs1;
use crate::{Address, Digest, ObjectId};
use sha3::{Digest as Sha3Digest, Sha3_256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum OwnerKind {
    AddressOwner = 0,
    ObjectOwner = 1,
    SharedOwner = 2,
    Immutable = 3,
}

impl OwnerKind {
    pub fn from_u8(v: u8) -> Result<Self, MisakaError> {
        match v {
            0 => Ok(Self::AddressOwner),
            1 => Ok(Self::ObjectOwner),
            2 => Ok(Self::SharedOwner),
            3 => Ok(Self::Immutable),
            _ => Err(MisakaError::DeserializationError(format!(
                "invalid OwnerKind: {v}"
            ))),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Object {
    pub id: ObjectId,
    pub version: u64,
    pub owner_kind: OwnerKind,
    pub owner: Address,
    pub type_tag: String,
    pub data: Vec<u8>,
}

impl Object {
    pub fn digest(&self) -> Digest {
        let mut buf = Vec::with_capacity(128 + self.data.len());
        mcs1::write_fixed(&mut buf, &self.id);
        mcs1::write_u64(&mut buf, self.version);
        mcs1::write_u8(&mut buf, self.owner_kind as u8);
        mcs1::write_fixed(&mut buf, &self.owner);
        mcs1::write_bytes(&mut buf, self.type_tag.as_bytes());
        mcs1::write_bytes(&mut buf, &self.data);
        let mut h = Sha3_256::new();
        h.update(&buf);
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_digest_deterministic() {
        let obj = Object {
            id: [0xAA; 32],
            version: 1,
            owner_kind: OwnerKind::AddressOwner,
            owner: [0xBB; 20],
            type_tag: "coin".into(),
            data: vec![1, 2, 3],
        };
        assert_eq!(obj.digest(), obj.digest());
    }
}
