use misaka_database::prelude::*;
use std::sync::Arc;

fn temp_db() -> (tempfile::TempDir, Arc<DB>) {
    let dir = tempfile::tempdir().expect("tmp");
    let db = ConnBuilder::default().build(dir.path()).expect("open");
    (dir, Arc::new(db))
}

#[test]
fn test_cached_db_access_write_read() {
    let (_dir, db) = temp_db();
    let access: CachedDbAccess<[u8; 32], Vec<u8>> =
        CachedDbAccess::new(db.clone(), CachePolicy::Count(100), vec![1]);
    let key = [42u8; 32];
    let value = vec![1, 2, 3, 4, 5];
    access
        .write(DirectDbWriter::new(db.clone()), key, value.clone())
        .expect("write");
    let read_back = access.read(key).expect("read");
    assert_eq!(read_back, value);
}

#[test]
fn test_cached_db_access_has_and_delete() {
    let (_dir, db) = temp_db();
    let access: CachedDbAccess<[u8; 32], Vec<u8>> =
        CachedDbAccess::new(db.clone(), CachePolicy::Count(100), vec![2]);
    let key = [7u8; 32];
    assert!(!access.has(key).expect("has1"));
    access
        .write(DirectDbWriter::new(db.clone()), key, vec![99])
        .expect("write");
    assert!(access.has(key).expect("has2"));
    access
        .delete(DirectDbWriter::new(db.clone()), key)
        .expect("delete");
    assert!(!access.has(key).expect("has3"));
}

#[test]
fn test_cached_db_item_roundtrip() {
    let (_dir, db) = temp_db();
    let mut item: CachedDbItem<u64> = CachedDbItem::new(db.clone(), vec![10, 20]);
    item.write(DirectDbWriter::new(db.clone()), &42u64)
        .expect("write");
    assert_eq!(item.read().expect("read"), 42);
}

#[test]
fn test_cached_db_item_update() {
    let (_dir, db) = temp_db();
    let mut item: CachedDbItem<u64> = CachedDbItem::new(db.clone(), vec![30, 40]);
    item.write(DirectDbWriter::new(db.clone()), &10u64)
        .expect("write");
    let updated = item
        .update(DirectDbWriter::new(db.clone()), |v| v + 5)
        .expect("update");
    assert_eq!(updated, 15);
}

#[test]
fn test_batch_writer_atomicity() {
    let (_dir, db) = temp_db();
    let access: CachedDbAccess<[u8; 32], Vec<u8>> =
        CachedDbAccess::new(db.clone(), CachePolicy::Count(100), vec![4]);
    let mut batch = misaka_database::rocksdb::WriteBatch::default();
    let k1 = [1u8; 32];
    let k2 = [2u8; 32];
    access
        .write(BatchDbWriter::new(&mut batch), k1, vec![10])
        .expect("w1");
    access
        .write(BatchDbWriter::new(&mut batch), k2, vec![20])
        .expect("w2");
    db.write(batch).expect("commit");
    assert_eq!(access.read(k1).expect("r1"), vec![10]);
    assert_eq!(access.read(k2).expect("r2"), vec![20]);
}

#[test]
fn test_cache_eviction() {
    use misaka_database::cache::Cache;
    let cache: Cache<u32, u32> = Cache::new(CachePolicy::Count(3));
    cache.insert(1, 10);
    cache.insert(2, 20);
    cache.insert(3, 30);
    assert_eq!(cache.len(), 3);
    cache.insert(4, 40);
    assert_eq!(cache.len(), 3);
}

#[test]
fn test_store_error_extensions() {
    let err: StoreResult<u32> = Err(StoreError::KeyNotFound("test".into()));
    assert!(err.optional().expect("optional").is_none());
    let dup: Result<(), StoreError> = Err(StoreError::KeyAlreadyExists("x".into()));
    dup.idempotent().expect("idempotent");
}

#[test]
fn test_memory_writer() {
    let mut writer = MemoryWriter::default();
    writer.put(b"key1", b"val1").expect("put");
    writer.put(b"key2", b"val2").expect("put");
    assert_eq!(writer.entries.len(), 2);
    writer.delete(b"key1").expect("del");
    assert_eq!(writer.entries.len(), 1);
    assert_eq!(writer.deleted.len(), 1);
}
