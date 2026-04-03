//! Topological sorting for transaction dependency ordering.

use std::collections::{HashMap, VecDeque};

/// Topological sort of transactions by their dependencies.
pub struct TopologicalSorter {
    /// Map from tx_id to its dependencies.
    dependencies: HashMap<[u8; 32], Vec<[u8; 32]>>,
    /// Reverse map: tx_id -> dependents.
    dependents: HashMap<[u8; 32], Vec<[u8; 32]>>,
}

impl TopologicalSorter {
    pub fn new() -> Self {
        Self {
            dependencies: HashMap::new(),
            dependents: HashMap::new(),
        }
    }

    /// Add a transaction with its dependencies.
    pub fn add(&mut self, tx_id: [u8; 32], deps: Vec<[u8; 32]>) {
        for dep in &deps {
            self.dependents.entry(*dep).or_default().push(tx_id);
        }
        self.dependencies.insert(tx_id, deps);
    }

    /// Remove a transaction.
    pub fn remove(&mut self, tx_id: &[u8; 32]) {
        if let Some(deps) = self.dependencies.remove(tx_id) {
            for dep in &deps {
                if let Some(rev) = self.dependents.get_mut(dep) {
                    rev.retain(|id| id != tx_id);
                }
            }
        }
        self.dependents.remove(tx_id);
    }

    /// Perform topological sort (Kahn's algorithm).
    pub fn sort(&self) -> Result<Vec<[u8; 32]>, TopologicalError> {
        let mut in_degree: HashMap<[u8; 32], usize> = HashMap::new();
        for (id, deps) in &self.dependencies {
            in_degree.entry(*id).or_insert(0);
            for dep in deps {
                if self.dependencies.contains_key(dep) {
                    *in_degree.entry(*id).or_insert(0) += 1;
                }
            }
        }

        let mut queue: VecDeque<[u8; 32]> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(id, _)| *id)
            .collect();

        let mut result = Vec::new();
        while let Some(id) = queue.pop_front() {
            result.push(id);
            if let Some(deps) = self.dependents.get(&id) {
                for dep_id in deps {
                    if let Some(deg) = in_degree.get_mut(dep_id) {
                        *deg = deg.saturating_sub(1);
                        if *deg == 0 {
                            queue.push_back(*dep_id);
                        }
                    }
                }
            }
        }

        if result.len() != self.dependencies.len() {
            return Err(TopologicalError::CycleDetected);
        }
        Ok(result)
    }

    /// Get transactions with no unresolved dependencies.
    pub fn ready_txs(&self) -> Vec<[u8; 32]> {
        self.dependencies
            .iter()
            .filter(|(_, deps)| deps.iter().all(|d| !self.dependencies.contains_key(d)))
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.dependencies.len()
    }
    pub fn is_empty(&self) -> bool {
        self.dependencies.is_empty()
    }
}

impl Default for TopologicalSorter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TopologicalError {
    #[error("cycle detected in transaction dependencies")]
    CycleDetected,
}

/// Trait for iterating transactions in topological order.
pub trait IntoIterTopologically {
    fn iter_topologically(&self) -> Vec<[u8; 32]>;
}
