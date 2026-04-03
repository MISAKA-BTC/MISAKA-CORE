//! Persistent store adapters for the UTXO index.

/// Trait for persisting UTXO index data.
pub trait UtxoIndexStore: Send + Sync {
    fn get(&self, script: &[u8]) -> Vec<super::UtxoEntry>;
    fn put(&self, script: &[u8], entries: &[super::UtxoEntry]);
    fn delete(&self, script: &[u8], outpoint: &super::Outpoint);
    fn count(&self) -> u64;
}
