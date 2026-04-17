use criterion::{black_box, criterion_group, criterion_main, Criterion};
use misaka_smt::{key, tree::SparseMerkleTree};

fn bench_insert(c: &mut Criterion) {
    c.bench_function("smt_insert_into_empty", |b| {
        b.iter(|| {
            let mut t = SparseMerkleTree::new();
            let k = key::smt_key(&[1u8; 32], 0);
            let v = key::smt_value(b"x");
            t.insert(black_box(k), black_box(v));
        });
    });

    let mut populated = SparseMerkleTree::new();
    for i in 0..1000u32 {
        let k = key::smt_key(&[i as u8; 32], i);
        let v = key::smt_value(&i.to_be_bytes());
        populated.insert(k, v);
    }
    c.bench_function("smt_insert_into_1000", |b| {
        b.iter(|| {
            let mut t = populated.clone();
            let k = key::smt_key(&[42u8; 32], 99999);
            let v = key::smt_value(b"new");
            t.insert(black_box(k), black_box(v));
        });
    });

    c.bench_function("smt_get_from_1000", |b| {
        let k = key::smt_key(&[5u8; 32], 5);
        b.iter(|| {
            let _ = populated.get(black_box(&k));
        });
    });

    c.bench_function("smt_prove_from_1000", |b| {
        let k = key::smt_key(&[5u8; 32], 5);
        b.iter(|| {
            let _ = populated.prove(black_box(&k));
        });
    });
}

criterion_group!(benches, bench_insert);
criterion_main!(benches);
