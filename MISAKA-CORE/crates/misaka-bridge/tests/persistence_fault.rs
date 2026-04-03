use misaka_bridge::persistence::BridgePersistence;

#[test]
fn test_corrupted_nullifier_rejects() {
    let dir = tempfile::tempdir().unwrap();
    let p = BridgePersistence::new(dir.path());
    std::fs::write(p.nullifier_path(), &[0u8; 33]).unwrap();
    assert!(p.validate_on_startup().is_err());
}

#[test]
fn test_corrupted_approval_json_rejects() {
    let dir = tempfile::tempdir().unwrap();
    let p = BridgePersistence::new(dir.path());
    std::fs::write(p.approval_path(), "not json {{{").unwrap();
    assert!(p.validate_on_startup().is_err());
}

#[test]
fn test_valid_empty_persistence_passes() {
    let dir = tempfile::tempdir().unwrap();
    let p = BridgePersistence::new(dir.path());
    assert!(p.validate_on_startup().is_ok());
}

#[test]
fn test_valid_nullifier_passes() {
    let dir = tempfile::tempdir().unwrap();
    let p = BridgePersistence::new(dir.path());
    // Write valid nullifier file (multiple of 32)
    std::fs::write(p.nullifier_path(), &[0u8; 64]).unwrap();
    assert!(p.validate_on_startup().is_ok());
}
