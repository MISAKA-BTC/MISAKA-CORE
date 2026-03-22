//! Safe mode / BFT liveness (Spec 16).
pub struct SafeMode {
    pub active: bool,
    pub missed_rounds: u64,
    pub threshold: u64,
}

impl SafeMode {
    pub fn new(threshold: u64) -> Self {
        Self {
            active: false,
            missed_rounds: 0,
            threshold,
        }
    }

    pub fn on_missed_round(&mut self) {
        self.missed_rounds += 1;
        if self.missed_rounds >= self.threshold {
            self.active = true;
        }
    }

    pub fn on_successful_round(&mut self) {
        self.missed_rounds = 0;
        self.active = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_safe_mode_trigger() {
        let mut sm = SafeMode::new(3);
        sm.on_missed_round();
        sm.on_missed_round();
        assert!(!sm.active);
        sm.on_missed_round();
        assert!(sm.active);
        sm.on_successful_round();
        assert!(!sm.active);
    }
}
