use misaka_notify::notification::*;
use misaka_notify::scope::Scope;
use misaka_notify::*;

#[tokio::test]
async fn test_register_and_notify() {
    let notifier = Notifier::new();
    let (_id, mut rx) = notifier.register_listener(Scope::all());

    notifier.notify(Notification::BlockAdded(BlockAddedNotification {
        hash: [1u8; 32],
    }));

    let msg = rx.recv().await.expect("recv");
    assert_eq!(msg.event_type(), EventType::BlockAdded);
}

#[tokio::test]
async fn test_scoped_subscription() {
    let notifier = Notifier::new();
    // Only subscribe to UTXO changes
    let (_id, mut rx) = notifier.register_listener(Scope::new(&[EventType::UtxosChanged]));

    // Send a BlockAdded — should NOT be received
    notifier.notify(Notification::BlockAdded(BlockAddedNotification {
        hash: [1u8; 32],
    }));

    // Send UtxosChanged — should be received
    notifier.notify(Notification::UtxosChanged(UtxosChangedNotification {
        added: vec![([2u8; 32], 100)],
        removed: vec![],
    }));

    let msg = rx.recv().await.expect("recv");
    assert_eq!(msg.event_type(), EventType::UtxosChanged);
}

#[tokio::test]
async fn test_unregister() {
    let notifier = Notifier::new();
    let (id, _rx) = notifier.register_listener(Scope::all());
    notifier.unregister_listener(id);

    // Should not panic even though listener is gone
    notifier.notify(Notification::BlockAdded(BlockAddedNotification {
        hash: [0u8; 32],
    }));
}

#[test]
fn test_event_types_all() {
    assert_eq!(EventType::ALL.len(), 10);
}
