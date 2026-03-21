#![no_main]
use libfuzzer_sys::fuzz_target;
use misaka_types::mcs1;

fuzz_target!(|data: &[u8]| {
    // Must never panic, regardless of input
    let mut off = 0;
    let _ = mcs1::read_u8(data, &mut off);
    off = 0;
    let _ = mcs1::read_u16(data, &mut off);
    off = 0;
    let _ = mcs1::read_u32(data, &mut off);
    off = 0;
    let _ = mcs1::read_u64(data, &mut off);
    off = 0;
    let _ = mcs1::read_u128(data, &mut off);
    off = 0;
    let _ = mcs1::read_bytes(data, &mut off);
});
