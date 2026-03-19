#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = misaka_pqc::bdlop::BalanceExcessProof::from_bytes(data);
});
