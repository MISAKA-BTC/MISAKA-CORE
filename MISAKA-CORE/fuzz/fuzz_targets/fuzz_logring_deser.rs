#![no_main]
use libfuzzer_sys::fuzz_target;
use misaka_pqc::logring::LogRingSignature;

fuzz_target!(|data: &[u8]| {
    // Must never panic, regardless of input
    let _ = LogRingSignature::from_bytes(data);
});
