#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic, regardless of input
    let _ = misaka_pqc::tx_codec::decode_transaction(data);
});
