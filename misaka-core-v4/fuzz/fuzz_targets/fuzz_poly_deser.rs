#![no_main]
use libfuzzer_sys::fuzz_target;
use misaka_pqc::pq_ring::Poly;

fuzz_target!(|data: &[u8]| {
    // Must never panic, regardless of input
    let _ = Poly::from_bytes(data);
});
