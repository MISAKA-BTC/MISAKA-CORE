use misaka_database::prelude::*;
use std::sync::Arc;

fn temp_db() -> (tempfile::TempDir, Arc<DB>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = ConnBuilder::default().build(dir.path()).expect("open db");
    (dir, Arc::new(db))
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct TestData {
    value: u64,
    name: String,
}
impl MemSizeEstimator for TestData {
    fn estimate_mem_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.name.len()
    }
}

#[test]
fn test_cached_db_access_roundtrip() {
    let (_dir, db) = temp_db();
    let access: CachedDbAccess<[u8; 4], TestData> =
        CachedDbAccess::new(db.clone(), CachePolicy::Count(100), vec![0x01]);

    let key = [1u8, 2, 3, 4];
    let data = TestData {
        value: 42,
        name: "hello".into(),
    };

    // Write
    access
        .write(DirectDbWriter::new(db.clone()), key, data.clone())
        .expect("write");

    // Read from cache
    let result = access.read(key).expect("read");
    assert_eq!(result, data);

    // Verify in DB (bypass cache via new access)
    let access2: CachedDbAccess<[u8; 4], TestData> =
        CachedDbAccess::new(db.clone(), CachePolicy::Empty, vec![0x01]);
    let result2 = access2.read(key).expect("read from db");
    assert_eq!(result2, data);
}

#[test]
fn test_cached_db_access_has_and_delete() {
    let (_dir, db) = temp_db();
    let access: CachedDbAccess<[u8; 4], TestData> =
        CachedDbAccess::new(db.clone(), CachePolicy::Count(100), vec![0x02]);

    let key = [5u8, 6, 7, 8];
    assert!(!access.has(key).expect("has before"));

    let data = TestData {
        value: 99,
        name: "test".into(),
    };
    access
        .write(DirectDbWriter::new(db.clone()), key, data)
        .expect("write");
    assert!(access.has(key).expect("has after"));

    access
        .delete(DirectDbWriter::new(db.clone()), key)
        .expect("delete");
    assert!(!access.has(key).expect("has after delete"));
}

#[test]
fn test_cached_db_item_roundtrip() {
    let (_dir, db) = temp_db();
    let mut item: CachedDbItem<TestData> = CachedDbItem::new(db.clone(), vec![0x10, 0x01]);

    let data = TestData {
        value: 123,
        name: "item".into(),
    };
    item.write(DirectDbWriter::new(db.clone()), &data)
        .expect("write");

    let result = item.read().expect("read");
    assert_eq!(result, data);

    // Update
    let updated = item
        .update(DirectDbWriter::new(db.clone()), |mut d| {
            d.value = 456;
            d
        })
        .expect("update");
    assert_eq!(updated.value, 456);
}

#[test]
fn test_batch_write() {
    let (_dir, db) = temp_db();
    let access: CachedDbAccess<[u8; 4], TestData> =
        CachedDbAccess::new(db.clone(), CachePolicy::Count(100), vec![0x03]);

    let mut batch = rocksdb::WriteBatch::default();
    for i in 0u8..10 {
        let key = [i, 0, 0, 0];
        let data = TestData {
            value: i as u64,
            name: format!("item_{}", i),
        };
        access
            .write(BatchDbWriter::new(&mut batch), key, data)
            .expect("batch write");
    }
    db.write(batch).expect("commit batch");

    for i in 0u8..10 {
        let key = [i, 0, 0, 0];
        let data = access.read(key).expect("read");
        assert_eq!(data.value, i as u64);
    }
}

#[test]
fn test_cache_eviction() {
    let cache = misaka_database::cache::Cache::<u64, u64>::new(CachePolicy::Count(3));
    cache.insert(1, 10);
    cache.insert(2, 20);
    cache.insert(3, 30);
    assert_eq!(cache.len(), 3);
    cache.insert(4, 40);
    assert_eq!(cache.len(), 3); // One evicted
}

#[test]
fn test_store_error_extensions() {
    let err: StoreResult<u64> = Err(StoreError::KeyNotFound("test".into()));
    let opt = err.optional().expect("optional");
    assert!(opt.is_none());

    let err2: StoreResult<()> = Err(StoreError::KeyAlreadyExists("test".into()));
    assert!(err2.idempotent().is_ok());
}
