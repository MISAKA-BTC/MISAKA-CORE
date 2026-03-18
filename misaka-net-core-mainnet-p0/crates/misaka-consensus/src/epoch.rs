//! Epoch boundary management (Spec 02 §5).
use misaka_types::Epoch;
use misaka_types::constants::EPOCH_LENGTH;

pub struct EpochManager {
    pub current_epoch: Epoch,
    pub checkpoints_in_epoch: u64,
}

impl EpochManager {
    pub fn new() -> Self { Self { current_epoch: 0, checkpoints_in_epoch: 0 } }

    pub fn on_checkpoint(&mut self) -> bool {
        self.checkpoints_in_epoch += 1;
        if self.checkpoints_in_epoch >= EPOCH_LENGTH {
            self.current_epoch += 1;
            self.checkpoints_in_epoch = 0;
            true // epoch boundary
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_epoch_boundary() {
        let mut em = EpochManager::new();
        for _ in 0..EPOCH_LENGTH - 1 {
            assert!(!em.on_checkpoint());
        }
        assert!(em.on_checkpoint());
        assert_eq!(em.current_epoch, 1);
    }
}
