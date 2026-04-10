//! Address tracker: monitors specific addresses for UTXO changes.

use crate::listener::ListenerId;
use std::collections::{HashMap, HashSet};

/// Tracks which listeners are watching which addresses.
pub struct AddressTracker {
    /// Map from address to listening IDs.
    by_address: HashMap<String, HashSet<ListenerId>>,
    /// Reverse map: listener -> addresses.
    by_listener: HashMap<ListenerId, HashSet<String>>,
    /// Maximum addresses per listener.
    max_per_listener: usize,
}

impl AddressTracker {
    pub fn new(max_per_listener: usize) -> Self {
        Self {
            by_address: HashMap::new(),
            by_listener: HashMap::new(),
            max_per_listener,
        }
    }

    /// Register addresses for a listener.
    pub fn register(
        &mut self,
        listener: ListenerId,
        addresses: Vec<String>,
    ) -> Result<(), AddressTrackError> {
        let current = self.by_listener.entry(listener).or_default();
        if current.len() + addresses.len() > self.max_per_listener {
            return Err(AddressTrackError::TooManyAddresses {
                current: current.len(),
                requested: addresses.len(),
                max: self.max_per_listener,
            });
        }

        for addr in addresses {
            self.by_address
                .entry(addr.clone())
                .or_default()
                .insert(listener);
            current.insert(addr);
        }
        Ok(())
    }

    /// Unregister addresses for a listener.
    pub fn unregister(&mut self, listener: &ListenerId, addresses: &[String]) {
        for addr in addresses {
            if let Some(listeners) = self.by_address.get_mut(addr) {
                listeners.remove(listener);
                if listeners.is_empty() {
                    self.by_address.remove(addr);
                }
            }
        }
        if let Some(addrs) = self.by_listener.get_mut(listener) {
            for addr in addresses {
                addrs.remove(addr);
            }
        }
    }

    /// Unregister all addresses for a listener.
    pub fn unregister_all(&mut self, listener: &ListenerId) {
        if let Some(addrs) = self.by_listener.remove(listener) {
            for addr in addrs {
                if let Some(listeners) = self.by_address.get_mut(&addr) {
                    listeners.remove(listener);
                    if listeners.is_empty() {
                        self.by_address.remove(&addr);
                    }
                }
            }
        }
    }

    /// Get listeners interested in a specific address.
    pub fn listeners_for_address(&self, address: &str) -> Vec<ListenerId> {
        self.by_address
            .get(address)
            .map_or_else(Vec::new, |s| s.iter().copied().collect())
    }

    /// Check if any listener is tracking a given address.
    pub fn is_tracked(&self, address: &str) -> bool {
        self.by_address.contains_key(address)
    }

    pub fn tracked_address_count(&self) -> usize {
        self.by_address.len()
    }
    pub fn listener_count(&self) -> usize {
        self.by_listener.len()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AddressTrackError {
    #[error("too many addresses: {current} + {requested} > {max}")]
    TooManyAddresses {
        current: usize,
        requested: usize,
        max: usize,
    },
}
