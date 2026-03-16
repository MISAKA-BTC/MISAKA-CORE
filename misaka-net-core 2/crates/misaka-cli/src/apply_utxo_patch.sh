#!/bin/bash
# apply_utxo_patch.sh — Apply UTXO reuse patch to misaka-net-core
# Run from the misaka-net-core root directory

set -e

echo "=== Applying UTXO reuse patch ==="

# 1. Patch pq_ring.rs — add derive_child + derive_address to SpendingKeypair
RING_FILE="crates/misaka-pqc/src/pq_ring.rs"
if grep -q "derive_child" "$RING_FILE"; then
    echo "  pq_ring.rs: already patched, skipping"
else
    # Insert before the closing } of impl SpendingKeypair
    # Find the line with canonical_key_image closing brace and insert after
    sed -i '/pub fn canonical_key_image/,/^    }/ {
        /^    }/ a\
\
    /// Derive a child spending keypair from master secret bytes + index.\
    /// index=0 is the master key (use from_ml_dsa). index=1+ are children.\
    /// Each child has a unique key_image, enabling UTXO reuse.\
    pub fn derive_child(master_sk_bytes: \&[u8], index: u32) -> Self {\
        use hkdf::Hkdf;\
        use sha2::Sha256;\
        assert!(index > 0, "index 0 is reserved for the master key");\
        let salt = format!("MISAKA:child:v1:{}", index);\
        let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), master_sk_bytes);\
        let mut child_bytes = vec![0u8; master_sk_bytes.len()];\
        hk.expand(b"misaka/child-spending-key", \&mut child_bytes)\
            .expect("HKDF expand for child key");\
        let child_sk = MlDsaSecretKey::from_bytes(\&child_bytes)\
            .expect("child key bytes must match ML-DSA SK length");\
        Self::from_ml_dsa(child_sk)\
    }\
\
    /// Derive the MISAKA address for this spending keypair.\
    pub fn derive_address(\&self) -> String {\
        use sha3::{Sha3_256, Digest};\
        let pub_bytes = self.public_poly.to_bytes();\
        let hash: [u8; 32] = {\
            let mut h = Sha3_256::new();\
            h.update(b"MISAKA:address:v1:");\
            h.update(\&pub_bytes);\
            h.finalize().into()\
        };\
        format!("msk1{}", hex::encode(\&hash[..20]))\
    }
    }' "$RING_FILE"
    echo "  pq_ring.rs: patched (derive_child + derive_address)"
fi

# 2. Copy new CLI files
CLI_SRC="crates/misaka-cli/src"

cp wallet_state.rs "$CLI_SRC/wallet_state.rs"
echo "  wallet_state.rs: created"

cp transfer.rs "$CLI_SRC/transfer.rs"
echo "  transfer.rs: updated"

cp faucet.rs "$CLI_SRC/faucet.rs"
echo "  faucet.rs: updated"

cp main.rs "$CLI_SRC/main.rs"
echo "  main.rs: updated"

# 3. Build
echo ""
echo "=== Building ==="
cargo build --release 2>&1 | tail -5

# 4. Test
echo ""
echo "=== Running tests ==="
cargo test -p misaka-cli 2>&1 | tail -5
cargo test -p misaka-pqc -- derive_child 2>&1 | tail -5

echo ""
echo "=== Patch applied successfully ==="
echo ""
echo "Usage:"
echo "  # Create wallet"
echo "  ./target/release/misaka-cli keygen --name alice"
echo "  mv wallet.key.json alice.key.json && mv wallet.pub.json alice.pub.json"
echo ""
echo "  # Faucet with UTXO tracking"
echo "  ./target/release/misaka-cli faucet <ADDRESS> --wallet alice.key.json --rpc http://localhost:3001"
echo ""
echo "  # Transfer (can repeat multiple times!)"
echo "  ./target/release/misaka-cli transfer --from alice.key.json --to <RECIPIENT> --amount 1000 --rpc http://localhost:3001"
echo ""
echo "  # Check state"
echo "  cat alice.state.json | python3 -m json.tool"
