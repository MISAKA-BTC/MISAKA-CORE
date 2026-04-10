//! Trait for estimating runtime memory consumption.

/// Trait for types that can estimate their heap memory usage.
pub trait MemSize {
    fn mem_size(&self) -> usize;
}

impl MemSize for String {
    fn mem_size(&self) -> usize {
        self.capacity()
    }
}

impl<T: MemSize> MemSize for Vec<T> {
    fn mem_size(&self) -> usize {
        std::mem::size_of::<T>() * self.capacity()
            + self.iter().map(|v| v.mem_size()).sum::<usize>()
    }
}

impl<T: MemSize> MemSize for Option<T> {
    fn mem_size(&self) -> usize {
        self.as_ref().map_or(0, |v| v.mem_size())
    }
}

impl MemSize for [u8; 32] {
    fn mem_size(&self) -> usize {
        0
    } // Inline, no heap
}

impl<K: MemSize, V: MemSize> MemSize for std::collections::HashMap<K, V> {
    fn mem_size(&self) -> usize {
        self.iter()
            .map(|(k, v)| k.mem_size() + v.mem_size())
            .sum::<usize>()
            + self.capacity() * (std::mem::size_of::<K>() + std::mem::size_of::<V>() + 8)
    }
}

impl MemSize for u64 {
    fn mem_size(&self) -> usize {
        0
    }
}
impl MemSize for u32 {
    fn mem_size(&self) -> usize {
        0
    }
}
impl MemSize for i64 {
    fn mem_size(&self) -> usize {
        0
    }
}
impl MemSize for bool {
    fn mem_size(&self) -> usize {
        0
    }
}
