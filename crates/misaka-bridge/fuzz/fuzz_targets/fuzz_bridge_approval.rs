#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz bridge receipt deserialization
    let _ = serde_json::from_slice::<misaka_bridge::BridgeReceipt>(data);
});
