use misaka_rpc::auth_middleware::{RpcAuthGuard, ReplayGuard};

#[test]
fn test_replay_guard_rejects_duplicate_nonce() {
    let mut guard = ReplayGuard::new(30);
    let key = [0xAA; 32];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    assert!(guard.check_replay(&key, 1, now).is_ok());
    assert!(guard.check_replay(&key, 1, now).is_err(), "duplicate nonce must fail");
}

#[test]
fn test_replay_guard_rejects_lower_nonce() {
    let mut guard = ReplayGuard::new(30);
    let key = [0xBB; 32];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    assert!(guard.check_replay(&key, 5, now).is_ok());
    assert!(guard.check_replay(&key, 3, now).is_err(), "lower nonce must fail");
}

#[test]
fn test_replay_guard_rejects_old_timestamp() {
    let mut guard = ReplayGuard::new(30);
    let key = [0xCC; 32];
    let old = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - 60;
    assert!(guard.check_replay(&key, 1, old).is_err(), "old timestamp must fail");
}

#[test]
fn test_replay_guard_rejects_future_timestamp() {
    let mut guard = ReplayGuard::new(30);
    let key = [0xDD; 32];
    let future = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 60;
    assert!(guard.check_replay(&key, 1, future).is_err(), "future timestamp must fail");
}

#[test]
fn test_auth_guard_deny_by_default() {
    let guard = RpcAuthGuard::new(None);
    assert!(guard.check_access("submitBlock", Some("any")).is_err());
    assert!(guard.check_access("shutdown", Some("any")).is_err());
    assert!(guard.check_access("getBlock", None).is_ok());
}

#[test]
fn test_admin_config_mainnet_rejects_public() {
    let public: std::net::SocketAddr = "0.0.0.0:3002".parse().unwrap();
    assert!(misaka_rpc::admin_listener::enforce_admin_config(
        &public, true, false, &None, &None
    ).is_err());
}

#[test]
fn test_admin_config_mtls_requires_both_paths() {
    let local: std::net::SocketAddr = "127.0.0.1:3002".parse().unwrap();
    assert!(misaka_rpc::admin_listener::enforce_admin_config(
        &local, true, true, &None, &None
    ).is_err());
    assert!(misaka_rpc::admin_listener::enforce_admin_config(
        &local, true, true, &Some("/nonexistent".into()), &None
    ).is_err());
}
