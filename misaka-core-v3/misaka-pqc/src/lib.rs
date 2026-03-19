//! MISAKA Post-Quantum Cryptography — Q-DAG-CT + Unified ZKP.
//!
//! # Cryptographic Stack
//!
//! | Layer          | Primitive           | Module              |
//! |----------------|---------------------|---------------------|
//! | Identity       | ML-DSA-65 (FIPS204) | `pq_sign`           |
//! | Stealth KEM    | ML-KEM-768 (FIPS203)| `pq_kem`            |
//! | Ring Algebra   | R_q = Z_q[X]/(X^256+1) | `pq_ring`, `ntt` |
//! | Membership     | Unified ZKP         | `unified_zkp`       |
//! | Nullifier      | Algebraic (a_null·s)| `nullifier`         |
//! | Commitment     | BDLOP (Module-SIS)  | `bdlop`             |
//! | Range Proof    | Bit-decomposition OR| `range_proof`       |
//! | Stealth Output | CT + ML-KEM         | `confidential_stealth` |
//! | Fee            | Confidential fee    | `confidential_fee`  |
//! | TX Structure   | Q-DAG-CT            | `qdag_tx`           |
//! | Secret Mgmt    | Zeroize-on-drop     | `secret`            |
//! | Privacy Policy | Padding + scan tag  | `privacy`           |

// ── Core PQ Crypto ──
pub mod error;
pub mod pq_sign;
pub mod pq_kem;
pub mod pq_ring;
pub mod ntt;
pub mod pq_stealth;

// ── Security Foundation ──
pub mod secret;

// ── Privacy Hardening ──
pub mod privacy;

// ── Unified ZKP (sole membership proof) ──
pub mod unified_zkp;

// ── Q-DAG-CT: Confidential Transactions ──
pub mod bdlop;
pub mod range_proof;
pub mod agg_range_proof;
pub mod qdag_tx;
pub mod nullifier;
pub mod confidential_stealth;
pub mod confidential_fee;

// ── Scheme versioning ──
pub mod ring_scheme;

// ═══════════════════════════════════════════════════════════════
//  Re-exports
// ═══════════════════════════════════════════════════════════════

pub use error::CryptoError;
pub use pq_sign::{MlDsaKeypair, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
pub use pq_kem::{MlKemKeypair, MlKemPublicKey, MlKemSecretKey, MlKemCiphertext, MlKemSharedSecret};
pub use pq_ring::{SpendingKeypair, Poly, derive_public_param, DEFAULT_A_SEED};
pub use pq_stealth::{StealthOutput, StealthScanner, RecoveredOutput, create_stealth_output};

pub use unified_zkp::{
    UnifiedMembershipProof, LevelOrProof,
    unified_prove, unified_verify, compute_merkle_root,
    SCHEME_UNIFIED_ZKP, ZKP_MIN_RING_SIZE, ZKP_MAX_RING_SIZE,
};

pub use bdlop::{
    BdlopCrs, BdlopCommitment, BlindingFactor, BalanceExcessProof,
    compute_balance_diff, verify_balance_with_excess, BDLOP_CRS_SEED,
};
pub use range_proof::{RangeProof, prove_range, verify_range, RANGE_BITS};
pub use agg_range_proof::{AggRangeProof, prove_agg_range, verify_agg_range, AGG_RANGE_BITS};
pub use qdag_tx::{
    QdagTransaction, QdagTxType, ConfidentialInput, ConfidentialOutput,
    ConfidentialStealthData, RingMemberLeaf, QDAG_VERSION,
};
pub use nullifier::{OutputId, NullifierProof, compute_nullifier, verify_nullifier};
pub use confidential_stealth::{
    CtStealthOutput, VerifiedCtOutput, CtStealthScanner,
    create_confidential_stealth, CT_STEALTH_VERSION,
};
pub use confidential_fee::{
    ConfidentialFee, FeeMinimumProof,
    create_confidential_fee, verify_confidential_fee, MIN_FEE, MAX_FEE,
};
pub use ring_scheme::MembershipSchemeVersion;
