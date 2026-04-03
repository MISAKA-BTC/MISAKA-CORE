//! Key Evolving Signature (KES) for MISAKA validators.
//!
//! Validator signing keys evolve every KES period. After evolution,
//! old key material is securely deleted (zeroized). This limits
//! the damage window if a key is compromised.
//!
//! Unlike Cardano's MMM-based KES, MISAKA uses HKDF-SHA3 chain
//! derivation since ML-DSA-65 doesn't support native KES.

use sha3::{Sha3_256, Digest};
use zeroize::Zeroize;

pub const DEFAULT_SLOTS_PER_KES_PERIOD: u64 = 129_600; // ~1.5 days at 1 slot/sec
pub const DEFAULT_MAX_KES_EVOLUTIONS: u32 = 62;

/// KES key state.
pub struct KesKeyState {
    current_period: u32,
    max_evolutions: u32,
    current_seed: Vec<u8>,
    start_period: u32,
}

impl KesKeyState {
    pub fn new(initial_seed: &[u8], start_period: u32, max_evolutions: u32) -> Self {
        let seed = Self::derive_seed(initial_seed, start_period);
        Self { current_period: start_period, max_evolutions, current_seed: seed, start_period }
    }

    pub fn current_period(&self) -> u32 { self.current_period }

    pub fn remaining_evolutions(&self) -> u32 {
        self.max_evolutions.saturating_sub(self.current_period - self.start_period)
    }

    pub fn can_evolve(&self) -> bool { self.remaining_evolutions() > 0 }

    /// Evolve to next period. Old seed is zeroized.
    pub fn evolve(&mut self) -> Result<(), KesError> {
        if !self.can_evolve() {
            return Err(KesError::MaxEvolutionsReached {
                current: self.current_period,
                max: self.start_period + self.max_evolutions,
            });
        }
        let next = self.current_period + 1;
        let new_seed = Self::derive_seed(&self.current_seed, next);
        self.current_seed.zeroize();
        self.current_seed = new_seed;
        self.current_period = next;
        Ok(())
    }

    /// Evolve to target period.
    pub fn evolve_to(&mut self, target: u32) -> Result<(), KesError> {
        if target < self.current_period {
            return Err(KesError::CannotDevolve { current: self.current_period, target });
        }
        while self.current_period < target { self.evolve()?; }
        Ok(())
    }

    pub fn signing_seed(&self) -> &[u8] { &self.current_seed }

    fn derive_seed(parent: &[u8], period: u32) -> Vec<u8> {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:kes:evolve:v1:");
        h.update(parent);
        h.update(&period.to_le_bytes());
        h.finalize().to_vec()
    }

    pub fn period_from_slot(slot: u64, slots_per_period: u64) -> u32 {
        (slot / slots_per_period) as u32
    }

    pub fn is_period_valid(period: u32, start: u32, max_evolutions: u32) -> bool {
        period >= start && period < start + max_evolutions
    }
}

impl Drop for KesKeyState {
    fn drop(&mut self) { self.current_seed.zeroize(); }
}

/// Operational certificate — authorizes a KES key for block production.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OperationalCertificate {
    pub kes_vkey: Vec<u8>,
    pub cert_serial: u64,
    pub start_kes_period: u32,
    pub cold_key_signature: Vec<u8>,
    pub cold_vkey: Vec<u8>,
}

impl OperationalCertificate {
    pub fn signing_payload(kes_vkey: &[u8], serial: u64, start_period: u32) -> Vec<u8> {
        let mut p = Vec::with_capacity(kes_vkey.len() + 12);
        p.extend_from_slice(b"MISAKA:opcert:v1:");
        p.extend_from_slice(kes_vkey);
        p.extend_from_slice(&serial.to_le_bytes());
        p.extend_from_slice(&start_period.to_le_bytes());
        p
    }

    pub fn is_valid_at(&self, current_period: u32, max_evolutions: u32) -> bool {
        KesKeyState::is_period_valid(current_period, self.start_kes_period, max_evolutions)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KesError {
    #[error("max KES evolutions reached: current={current}, max={max}")]
    MaxEvolutionsReached { current: u32, max: u32 },
    #[error("cannot devolve: current={current}, target={target}")]
    CannotDevolve { current: u32, target: u32 },
    #[error("KES period expired")]
    PeriodExpired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kes_evolve() {
        let mut state = KesKeyState::new(b"seed_for_kes_test_32bytes_pad!!", 0, 62);
        assert_eq!(state.current_period(), 0);
        state.evolve().unwrap();
        assert_eq!(state.current_period(), 1);
        assert_eq!(state.remaining_evolutions(), 61);
    }

    #[test]
    fn test_kes_max_evolutions() {
        let mut state = KesKeyState::new(b"seed_for_max_kes_evolution_test!", 0, 3);
        state.evolve().unwrap();
        state.evolve().unwrap();
        state.evolve().unwrap();
        assert!(state.evolve().is_err());
    }

    #[test]
    fn test_kes_seeds_differ() {
        let mut state = KesKeyState::new(b"seed_for_different_period_test!", 0, 62);
        let s0 = state.signing_seed().to_vec();
        state.evolve().unwrap();
        assert_ne!(s0, state.signing_seed());
    }

    #[test]
    fn test_opcert_valid() {
        let cert = OperationalCertificate {
            kes_vkey: vec![1; 32], cert_serial: 1, start_kes_period: 0,
            cold_key_signature: vec![], cold_vkey: vec![],
        };
        assert!(cert.is_valid_at(0, 62));
        assert!(cert.is_valid_at(61, 62));
        assert!(!cert.is_valid_at(62, 62));
    }

    #[test]
    fn test_period_from_slot() {
        assert_eq!(KesKeyState::period_from_slot(0, 129600), 0);
        assert_eq!(KesKeyState::period_from_slot(129599, 129600), 0);
        assert_eq!(KesKeyState::period_from_slot(129600, 129600), 1);
    }
}
