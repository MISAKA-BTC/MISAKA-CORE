use misaka_dag_types::block::Transaction;
use std::time::{Duration, Instant};

pub struct BatchMaker {
    config: super::WorkerConfig,
    current_batch: Vec<Transaction>,
    current_size: usize,
    last_seal: Instant,
}

impl BatchMaker {
    pub fn new(config: super::WorkerConfig) -> Self {
        Self { config, current_batch: Vec::new(), current_size: 0, last_seal: Instant::now() }
    }

    pub fn add_transaction(&mut self, tx: Transaction) -> Option<Vec<Transaction>> {
        self.current_size += tx.len();
        self.current_batch.push(tx);
        if self.current_size >= self.config.batch_size {
            return Some(self.seal());
        }
        None
    }

    pub fn check_timeout(&mut self) -> Option<Vec<Transaction>> {
        if !self.current_batch.is_empty()
            && self.last_seal.elapsed() >= Duration::from_millis(self.config.batch_timeout_ms)
        {
            return Some(self.seal());
        }
        None
    }

    fn seal(&mut self) -> Vec<Transaction> {
        self.current_size = 0;
        self.last_seal = Instant::now();
        std::mem::take(&mut self.current_batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_batch_seal_on_size() {
        let cfg = super::super::WorkerConfig { batch_size: 100, batch_timeout_ms: 5000, worker_id: 0 };
        let mut maker = BatchMaker::new(cfg);
        assert!(maker.add_transaction(vec![0u8; 50]).is_none());
        let batch = maker.add_transaction(vec![0u8; 60]);
        assert!(batch.is_some());
        assert_eq!(batch.as_ref().map(|b| b.len()), Some(2));
    }
}
