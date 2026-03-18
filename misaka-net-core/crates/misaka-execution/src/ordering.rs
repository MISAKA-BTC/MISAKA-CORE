//! DET_ORDER_V1: Transaction ordering (Spec 03 §7).
use misaka_types::transaction::{Transaction, TxClass};
use misaka_types::Digest;

pub struct OrderedTx { pub tx: Transaction, pub tx_hash: Digest, pub class: TxClass }

pub fn deterministic_order(txs: Vec<Transaction>) -> Vec<OrderedTx> {
    let mut items: Vec<OrderedTx> = txs.into_iter().map(|tx| {
        let tx_hash = tx.tx_hash();
        let class = tx.tx_class();
        OrderedTx { tx, tx_hash, class }
    }).collect();
    items.sort_by(|a, b| {
        match (&a.class, &b.class) {
            (TxClass::Shared, TxClass::OwnedOnly) => std::cmp::Ordering::Less,
            (TxClass::OwnedOnly, TxClass::Shared) => std::cmp::Ordering::Greater,
            _ => a.tx_hash.cmp(&b.tx_hash),
        }
    });
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_types::scheme::{MisakaPublicKey, MisakaSignature, SignatureScheme};
    use misaka_types::transaction::*;

    fn make_tx(id_byte: u8, shared: bool) -> Transaction {
        Transaction {
            sender: MisakaPublicKey { scheme: SignatureScheme::MlDsa65, bytes: vec![id_byte; 1952] },
            inputs: vec![InputRef {
                object_id: [id_byte; 32],
                kind: if shared { InputKind::Shared } else { InputKind::Owned },
                access: AccessMode::Mutable,
                expected_version: None, expected_digest: None,
            }],
            actions: vec![Action { module: "m".into(), function: "f".into(), args: vec![] }],
            gas_budget: 1000, gas_price: 1, expiration_epoch: None,
            signature: MisakaSignature::ml_dsa(vec![0; 3309]),
        }
    }

    #[test]
    fn test_shared_before_owned() {
        let txs = vec![make_tx(0xAA, false), make_tx(0xBB, true)];
        let ordered = deterministic_order(txs);
        assert_eq!(ordered[0].class, TxClass::Shared);
    }
}
