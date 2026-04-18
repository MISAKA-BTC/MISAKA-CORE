use criterion::{black_box, criterion_group, criterion_main, Criterion};
use misaka_muhash::MuHash;

fn bench_add_element(c: &mut Criterion) {
    c.bench_function("muhash3072_add_element", |b| {
        let mut mh = MuHash::new();
        let data = b"bench_utxo_element_0123456789abcdef";
        b.iter(|| {
            mh.add_element(black_box(data));
        });
    });
}

fn bench_remove_element(c: &mut Criterion) {
    c.bench_function("muhash3072_remove_element", |b| {
        let mut mh = MuHash::new();
        mh.add_element(b"existing_element");
        let data = b"bench_utxo_element_0123456789abcdef";
        b.iter(|| {
            mh.remove_element(black_box(data));
        });
    });
}

fn bench_finalize(c: &mut Criterion) {
    c.bench_function("muhash3072_finalize", |b| {
        let mut mh = MuHash::new();
        for i in 0u32..100 {
            mh.add_element(&i.to_le_bytes());
        }
        b.iter(|| {
            black_box(mh.finalize());
        });
    });
}

fn bench_combine(c: &mut Criterion) {
    c.bench_function("muhash3072_combine", |b| {
        let mut mh1 = MuHash::new();
        mh1.add_element(b"a");
        let mut mh2 = MuHash::new();
        mh2.add_element(b"b");
        b.iter(|| {
            let mut tmp = mh1.clone();
            tmp.combine(black_box(&mh2));
        });
    });
}

criterion_group!(
    benches,
    bench_add_element,
    bench_remove_element,
    bench_finalize,
    bench_combine
);
criterion_main!(benches);
