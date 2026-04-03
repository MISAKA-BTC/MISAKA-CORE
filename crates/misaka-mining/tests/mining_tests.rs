use misaka_mining::fee_rate::{calc_tx_mass, FeeRate};
use misaka_mining::mempool::config::MempoolConfig;
use misaka_mining::mempool::model::MempoolTransaction;
use misaka_mining::mempool::Mempool;
use misaka_mining::MiningManager;

fn test_tx(id: u8, fee: u64, mass: u64) -> MempoolTransaction {
    let mut tx_id = [0u8; 32];
    tx_id[0] = id;
    MempoolTransaction::new(tx_id, vec![1, 2, 3], fee, mass, false)
}

#[test]
fn test_mempool_add_and_select() {
    let mut pool = Mempool::new(MempoolConfig::default());
    pool.add_transaction(test_tx(1, 100, 50)).expect("add tx1");
    pool.add_transaction(test_tx(2, 200, 50)).expect("add tx2");
    pool.add_transaction(test_tx(3, 50, 50)).expect("add tx3");
    assert_eq!(pool.transaction_count(), 3);

    // Select top 2 by fee rate
    let selected = pool.select_transactions(2);
    assert_eq!(selected.len(), 2);
    // Highest fee rate first (200/50=4.0, then 100/50=2.0)
    assert_eq!(selected[0].fee, 200);
    assert_eq!(selected[1].fee, 100);
}

#[test]
fn test_mempool_remove() {
    let mut pool = Mempool::new(MempoolConfig::default());
    pool.add_transaction(test_tx(1, 100, 50)).expect("add");
    assert_eq!(pool.transaction_count(), 1);

    let mut id = [0u8; 32];
    id[0] = 1;
    pool.remove_transaction(&id);
    assert_eq!(pool.transaction_count(), 0);
}

#[test]
fn test_mempool_duplicate() {
    let mut pool = Mempool::new(MempoolConfig::default());
    pool.add_transaction(test_tx(1, 100, 50)).expect("add");
    assert!(pool.add_transaction(test_tx(1, 100, 50)).is_err());
}

#[test]
fn test_mempool_eviction() {
    let config = MempoolConfig {
        max_pool_size: 3,
        ..Default::default()
    };
    let mut pool = Mempool::new(config);
    pool.add_transaction(test_tx(1, 10, 50)).expect("add");
    pool.add_transaction(test_tx(2, 20, 50)).expect("add");
    pool.add_transaction(test_tx(3, 30, 50)).expect("add");
    assert_eq!(pool.transaction_count(), 3);

    // Adding higher fee rate should evict lowest
    pool.add_transaction(test_tx(4, 100, 50))
        .expect("add better");
    assert_eq!(pool.transaction_count(), 3);

    // Adding lower fee rate should fail
    assert!(pool.add_transaction(test_tx(5, 1, 50)).is_err());
}

#[test]
fn test_fee_rate() {
    assert_eq!(FeeRate::new(100, 50), FeeRate(2.0));
    assert_eq!(FeeRate::new(0, 50), FeeRate(0.0));
    assert_eq!(FeeRate::new(100, 0), FeeRate(0.0));
    assert!(FeeRate::new(100, 50) > FeeRate::new(50, 50));
}

#[test]
fn test_tx_mass() {
    let mass = calc_tx_mass(100, 2048);
    assert_eq!(mass, 2148);
}

#[test]
fn test_mining_manager() {
    let mgr = MiningManager::new(MempoolConfig::default());
    mgr.submit_transaction(test_tx(1, 100, 50)).expect("submit");
    mgr.submit_transaction(test_tx(2, 200, 50)).expect("submit");
    assert_eq!(mgr.transaction_count(), 2);

    let template = mgr.get_block_template(
        vec![[0u8; 32]],
        1000,
        0x1d00ffff,
        5,
        vec![1, 2, 3],
        50_000_000_000,
    );
    assert_eq!(template.transactions.len(), 2);
    assert_eq!(template.total_fees, 300);
    assert_eq!(template.coinbase_data.reward_amount, 50_000_000_300);

    // Handle new block
    let mut id1 = [0u8; 32];
    id1[0] = 1;
    let mut id2 = [0u8; 32];
    id2[0] = 2;
    mgr.handle_new_block(&[id1, id2]);
    assert_eq!(mgr.transaction_count(), 0);
}
