#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 { return; }
    let guard = misaka_rpc::auth_middleware::RpcAuthGuard::new(Some("fuzz_key"));
    if let Ok(token) = std::str::from_utf8(data) {
        let _ = guard.check_access("submitBlock", Some(token));
    }
});
