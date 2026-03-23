//! MCS-1: MISAKA Canonical Serialization v1
//!
//! Deterministic binary encoding for all on-chain structures.
//! Rules: fixed-width integers (little-endian), length-prefixed byte arrays,
//! fields in declaration order, no padding.

use crate::error::MisakaError;

pub fn write_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}

pub fn write_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

pub fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

pub fn write_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

pub fn write_u128(buf: &mut Vec<u8>, v: u128) {
    buf.extend_from_slice(&v.to_le_bytes());
}

pub fn write_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    write_u32(buf, data.len() as u32);
    buf.extend_from_slice(data);
}

pub fn write_fixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(data);
}

pub fn read_u8(data: &[u8], offset: &mut usize) -> Result<u8, MisakaError> {
    if *offset >= data.len() {
        return Err(MisakaError::DeserializationError("EOF reading u8".into()));
    }
    let v = data[*offset];
    *offset += 1;
    Ok(v)
}

pub fn read_u16(data: &[u8], offset: &mut usize) -> Result<u16, MisakaError> {
    if *offset + 2 > data.len() {
        return Err(MisakaError::DeserializationError("EOF reading u16".into()));
    }
    let v = u16::from_le_bytes([data[*offset], data[*offset + 1]]);
    *offset += 2;
    Ok(v)
}

pub fn read_u32(data: &[u8], offset: &mut usize) -> Result<u32, MisakaError> {
    if *offset + 4 > data.len() {
        return Err(MisakaError::DeserializationError("EOF reading u32".into()));
    }
    let v =
        u32::from_le_bytes(data[*offset..*offset + 4].try_into().map_err(|_| {
            MisakaError::DeserializationError("u32 slice conversion failed".into())
        })?);
    *offset += 4;
    Ok(v)
}

pub fn read_u64(data: &[u8], offset: &mut usize) -> Result<u64, MisakaError> {
    if *offset + 8 > data.len() {
        return Err(MisakaError::DeserializationError("EOF reading u64".into()));
    }
    let v =
        u64::from_le_bytes(data[*offset..*offset + 8].try_into().map_err(|_| {
            MisakaError::DeserializationError("u64 slice conversion failed".into())
        })?);
    *offset += 8;
    Ok(v)
}

pub fn read_u128(data: &[u8], offset: &mut usize) -> Result<u128, MisakaError> {
    if *offset + 16 > data.len() {
        return Err(MisakaError::DeserializationError("EOF reading u128".into()));
    }
    let v =
        u128::from_le_bytes(data[*offset..*offset + 16].try_into().map_err(|_| {
            MisakaError::DeserializationError("u128 slice conversion failed".into())
        })?);
    *offset += 16;
    Ok(v)
}

pub fn read_bytes(data: &[u8], offset: &mut usize) -> Result<Vec<u8>, MisakaError> {
    let len = read_u32(data, offset)? as usize;
    if *offset + len > data.len() {
        return Err(MisakaError::DeserializationError(
            "EOF reading bytes".into(),
        ));
    }
    let v = data[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(v)
}

pub fn read_fixed(data: &[u8], offset: &mut usize, len: usize) -> Result<Vec<u8>, MisakaError> {
    if *offset + len > data.len() {
        return Err(MisakaError::DeserializationError(
            "EOF reading fixed bytes".into(),
        ));
    }
    let v = data[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u64_roundtrip() {
        let mut buf = Vec::new();
        write_u64(&mut buf, 0xDEADBEEF_CAFEBABE);
        let mut offset = 0;
        assert_eq!(read_u64(&buf, &mut offset).unwrap(), 0xDEADBEEF_CAFEBABE);
    }

    #[test]
    fn test_bytes_roundtrip() {
        let mut buf = Vec::new();
        write_bytes(&mut buf, b"MISAKA");
        let mut offset = 0;
        assert_eq!(read_bytes(&buf, &mut offset).unwrap(), b"MISAKA");
    }
}
