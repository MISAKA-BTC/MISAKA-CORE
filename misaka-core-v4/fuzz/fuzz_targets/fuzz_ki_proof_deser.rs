#![no_main]
use libfuzzer_sys::fuzz_target;
use misaka_pqc::ki_proof::KiProof;

fuzz_target!(|data: &[u8]| {
    // Must never panic, regardless of input
    let _ = KiProof::from_bytes(data);
});
