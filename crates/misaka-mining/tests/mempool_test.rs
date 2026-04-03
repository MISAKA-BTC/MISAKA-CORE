use misaka_mining::fee_rate::FeeRate;
use misaka_mining::mempool::config::MempoolConfig;
use misaka_mining::mempool::model::MempoolTransaction;
use misaka_mining::mempool::Mempool;

fn test_tx(id_byte: u8, fee: u64, mass: u64) -> MempoolTransaction {
    let mut id = [0u8; 32];
    id[0] = id_byte;
    MempoolTransaction::new(id, vec![1, 2, 3], fee, mass, false)
}

#[test]
fn test_add_and_select() {
    let mut pool = Mempool::new(MempoolConfig {
        max_pool_size: 100,
        ..Default::default()
    });
    pool.add_transaction(test_tx(1, 100, 10)).expect("add1");
    pool.add_transaction(test_tx(2, 200, 10)).expect("add2");
    pool.add_transaction(test_tx(3, 50, 10)).expect("add3");
    assert_eq!(pool.transaction_count(), 3);

    let selected = pool.select_transactions(2);
    assert_eq!(selected.len(), 2);
    // Highest fee rate first
    assert_eq!(selected[0].fee, 200);
    assert_eq!(selected[1].fee, 100);
}

#[test]
fn test_remove_transaction() {
    let mut pool = Mempool::new(MempoolConfig::default());
    let tx = test_tx(1, 100, 10);
    let id = tx.id;
    pool.add_transaction(tx).expect("add");
    assert_eq!(pool.transaction_count(), 1);
    pool.remove_transaction(&id);
    assert_eq!(pool.transaction_count(), 0);
}

#[test]
fn test_duplicate_rejected() {
    let mut pool = Mempool::new(MempoolConfig::default());
    pool.add_transaction(test_tx(1, 100, 10)).expect("add1");
    assert!(pool.add_transaction(test_tx(1, 100, 10)).is_err());
}

#[test]
fn test_pool_eviction() {
    let mut pool = Mempool::new(MempoolConfig {
        max_pool_size: 2,
        ..Default::default()
    });
    pool.add_transaction(test_tx(1, 100, 10)).expect("add1");
    pool.add_transaction(test_tx(2, 200, 10)).expect("add2");
    // Adding higher fee tx should evict lowest
    pool.add_transaction(test_tx(3, 300, 10)).expect("add3");
    assert_eq!(pool.transaction_count(), 2);
    let selected = pool.select_transactions(10);
    let fees: Vec<u64> = selected.iter().map(|t| t.fee).collect();
    assert!(fees.contains(&300));
    assert!(fees.contains(&200));
}

#[test]
fn test_fee_rate() {
    assert_eq!(FeeRate::new(100, 50), FeeRate(2.0));
    assert_eq!(FeeRate::new(0, 100), FeeRate(0.0));
    assert_eq!(FeeRate::new(100, 0), FeeRate(0.0));
    assert!(FeeRate::new(200, 50) > FeeRate::new(100, 50));
}
