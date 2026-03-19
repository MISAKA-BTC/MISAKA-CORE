#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz NullifierProof deserialization — must never panic
    let _ = misaka_pqc::nullifier::NullifierProof::from_bytes(data);
});
