//! v5 utxo_element_bytes: includes datum and script_ref hashes.

use super::domain::*;
use super::extended_output::ExtendedOutput;
use misaka_types::eutxo::datum::DatumOrHash;
use misaka_types::utxo::OutputRef;
use sha3::{Digest, Sha3_256};

pub fn datum_hash_canonical(datum: &Option<DatumOrHash>) -> [u8; 32] {
    match datum {
        None => [0u8; 32],
        Some(DatumOrHash::Hash(h)) => *h,
        Some(DatumOrHash::Inline(d)) => {
            let mut h = Sha3_256::new();
            h.update(DATUM_BODY_HASH);
            h.update(&d.0);
            h.finalize().into()
        }
    }
}

pub fn script_ref_hash_canonical(
    script_ref: &Option<misaka_types::eutxo::script::VersionedScript>,
) -> [u8; 32] {
    match script_ref {
        None => [0u8; 32],
        Some(vs) => {
            let mut h = Sha3_256::new();
            h.update(SCRIPT_BODY_HASH);
            h.update(&[vs.vm_version as u8]);
            h.update(&vs.bytecode.0);
            h.finalize().into()
        }
    }
}

pub fn extended_output_hash(out: &ExtendedOutput) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(EXTENDED_OUTPUT_CANONICAL);
    let addr_bytes = borsh::to_vec(&out.address).expect("borsh address");
    h.update(&addr_bytes);
    let value_bytes = borsh::to_vec(&out.value).expect("borsh value");
    h.update(&value_bytes);
    let pk_bytes = borsh::to_vec(&out.spending_pubkey).expect("borsh pk");
    h.update(&pk_bytes);
    h.update(datum_hash_canonical(&out.datum));
    h.update(script_ref_hash_canonical(&out.script_ref));
    h.finalize().into()
}

pub fn utxo_element_bytes_v5(outref: &OutputRef, output: &ExtendedOutput, height: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(MUHASH_UTXO_ELEMENT_V5);
    let outref_bytes = borsh::to_vec(outref).expect("borsh outref");
    buf.extend_from_slice(&outref_bytes);
    buf.extend_from_slice(&extended_output_hash(output));
    buf.extend_from_slice(&height.to_le_bytes());
    buf
}
