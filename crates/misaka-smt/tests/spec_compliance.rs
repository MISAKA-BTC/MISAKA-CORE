//! Public spec compliance tests. These tests pin the v1 SMT specification
//! and MUST pass for any compliant implementation.

use misaka_smt::*;

#[test]
fn empty_root_is_deterministic() {
    let t1 = tree::SparseMerkleTree::new();
    let t2 = tree::SparseMerkleTree::new();
    assert_eq!(t1.root(), t2.root());
}

#[test]
fn insert_then_get() {
    let mut t = tree::SparseMerkleTree::new();
    let k = key::smt_key(&[1u8; 32], 0);
    let v = key::smt_value(b"hello");
    t.insert(k, v);
    assert_eq!(t.get(&k), Some(v));
}

#[test]
fn insert_then_remove_returns_to_empty() {
    let mut t = tree::SparseMerkleTree::new();
    let empty = t.root();
    let k = key::smt_key(&[2u8; 32], 0);
    let v = key::smt_value(b"x");
    t.insert(k, v);
    assert_ne!(t.root(), empty);
    assert!(t.remove(&k));
    assert_eq!(t.root(), empty);
}

#[test]
fn inclusion_proof_verifies() {
    let mut t = tree::SparseMerkleTree::new();
    for i in 0..50u32 {
        let k = key::smt_key(&[i as u8; 32], i);
        let v = key::smt_value(&[i as u8; 16]);
        t.insert(k, v);
    }
    let root = t.root();
    for i in 0..50u32 {
        let k = key::smt_key(&[i as u8; 32], i);
        let proof = t.prove(&k);
        assert!(proof.verify_inclusion(&root), "inclusion failed at i={}", i);
        assert!(!proof.verify_exclusion(&root));
    }
}

#[test]
fn exclusion_proof_verifies() {
    let mut t = tree::SparseMerkleTree::new();
    for i in 0..50u32 {
        let k = key::smt_key(&[i as u8; 32], i);
        let v = key::smt_value(&[i as u8; 16]);
        t.insert(k, v);
    }
    let root = t.root();
    let absent = key::smt_key(&[0xFFu8; 32], 999);
    let proof = t.prove(&absent);
    assert!(proof.verify_exclusion(&root));
    assert!(!proof.verify_inclusion(&root));
}

#[test]
fn proof_serialization_roundtrip() {
    let mut t = tree::SparseMerkleTree::new();
    let k = key::smt_key(&[3u8; 32], 0);
    let v = key::smt_value(b"y");
    t.insert(k, v);
    let proof = t.prove(&k);
    let bytes = borsh::to_vec(&proof).expect("SmtProof borsh serialization must not fail");
    let decoded: proof::SmtProof =
        borsh::from_slice(&bytes).expect("SmtProof borsh deserialization must not fail");
    assert_eq!(proof, decoded);
    assert!(decoded.verify_inclusion(&t.root()));
}

#[test]
fn batch_apply_matches_sequential() {
    let mut a = tree::SparseMerkleTree::new();
    let mut b = tree::SparseMerkleTree::new();
    let mut batch_op = batch::UpdateBatch::new();
    for i in 0..100u32 {
        let k = key::smt_key(&[i as u8; 32], i);
        let v = key::smt_value(&i.to_be_bytes());
        a.insert(k, v);
        batch_op.upserts.push((k, v));
    }
    let root_b = batch_op.apply(&mut b);
    assert_eq!(a.root(), root_b);
}

#[test]
fn order_independence() {
    let pairs: Vec<_> = (0..50u32)
        .map(|i| {
            (
                key::smt_key(&[i as u8; 32], i),
                key::smt_value(&[i as u8; 8]),
            )
        })
        .collect();
    let mut a = tree::SparseMerkleTree::new();
    for (k, v) in &pairs {
        a.insert(*k, *v);
    }
    let mut b = tree::SparseMerkleTree::new();
    for (k, v) in pairs.iter().rev() {
        b.insert(*k, *v);
    }
    assert_eq!(a.root(), b.root());
}

#[test]
fn domain_separation_prevents_collision() {
    // leaf_hash(k, v) MUST differ from internal_hash(k, v)
    let k = [1u8; 32];
    let v = [2u8; 32];
    assert_ne!(hash::leaf_hash(&k, &v), hash::internal_hash(&k, &v));
}

#[test]
fn empty_hashes_chain_correctly() {
    for d in 1..=domain::SMT_DEPTH {
        let expected = hash::internal_hash(&empty::empty_hash(d - 1), &empty::empty_hash(d - 1));
        assert_eq!(
            empty::empty_hash(d),
            expected,
            "empty hash chain broken at depth {}",
            d
        );
    }
}
