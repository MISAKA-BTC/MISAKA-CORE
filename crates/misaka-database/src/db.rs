//! RocksDB wrapper with preset configurations.

use rocksdb::{DBWithThreadMode, MultiThreaded, Options};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};

/// The DB type used for all MISAKA stores.
pub struct DB {
    inner: DBWithThreadMode<MultiThreaded>,
}

impl DB {
    pub fn new(inner: DBWithThreadMode<MultiThreaded>) -> Self {
        Self { inner }
    }
}

impl Deref for DB {
    type Target = DBWithThreadMode<MultiThreaded>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for DB {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// Deletes an existing DB directory.
pub fn delete_db(db_dir: PathBuf) {
    if !db_dir.exists() {
        return;
    }
    let options = Options::default();
    if let Some(path) = db_dir.to_str() {
        let _ = <DBWithThreadMode<MultiThreaded>>::destroy(&options, path);
    }
}

/// Builder for database connections with preset configurations.
pub struct ConnBuilder {
    parallelism: i32,
    create_if_missing: bool,
    files_limit: i32,
}

impl Default for ConnBuilder {
    fn default() -> Self {
        Self {
            parallelism: 4,
            create_if_missing: true,
            files_limit: 512,
        }
    }
}

impl ConnBuilder {
    pub fn parallelism(mut self, parallelism: i32) -> Self {
        self.parallelism = parallelism;
        self
    }

    pub fn create_if_missing(mut self, flag: bool) -> Self {
        self.create_if_missing = flag;
        self
    }

    pub fn files_limit(mut self, limit: i32) -> Self {
        self.files_limit = limit;
        self
    }

    pub fn build(self, path: &Path) -> Result<DB, rocksdb::Error> {
        let mut opts = Options::default();
        opts.create_if_missing(self.create_if_missing);
        opts.increase_parallelism(self.parallelism);
        opts.set_max_open_files(self.files_limit);
        // Performance optimizations
        opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB
        opts.set_max_write_buffer_number(3);
        opts.set_target_file_size_base(64 * 1024 * 1024);
        opts.set_level_compaction_dynamic_level_bytes(true);
        opts.set_bytes_per_sync(1048576);
        opts.set_compaction_readahead_size(2 * 1024 * 1024);

        let inner = DBWithThreadMode::<MultiThreaded>::open(&opts, path)?;
        Ok(DB::new(inner))
    }
}
