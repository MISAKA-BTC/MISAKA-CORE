use misaka_notify::notification::*;
use misaka_notify::scope::Scope;
use misaka_notify::*;

#[tokio::test]
async fn test_notifier_basic() {
    let notifier = Notifier::new();

    let (id, mut rx) = notifier.register_listener(Scope::all());
    assert!(id > 0);

    notifier.notify(Notification::BlockAdded(BlockAddedNotification {
        hash: [1u8; 32],
    }));

    let msg = rx.recv().await.expect("recv");
    assert!(matches!(msg, Notification::BlockAdded(_)));
}

#[tokio::test]
async fn test_notifier_scoped() {
    let notifier = Notifier::new();

    // Only subscribe to block events
    let (_id, mut rx) = notifier.register_listener(Scope::new(&[EventType::BlockAdded]));

    // Send a block notification (should arrive)
    notifier.notify(Notification::BlockAdded(BlockAddedNotification {
        hash: [1u8; 32],
    }));

    // Send a DAA score notification (should NOT arrive)
    notifier.notify(Notification::VirtualDaaScoreChanged(
        VirtualDaaScoreChangedNotification {
            virtual_daa_score: 100,
        },
    ));

    let msg = rx.recv().await.expect("recv");
    assert!(matches!(msg, Notification::BlockAdded(_)));

    // Channel should be empty (DAA was filtered)
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn test_notifier_unregister() {
    let notifier = Notifier::new();
    let (id, _rx) = notifier.register_listener(Scope::all());
    notifier.unregister_listener(id);

    // Should not panic even with no listeners
    notifier.notify(Notification::BlockAdded(BlockAddedNotification {
        hash: [0u8; 32],
    }));
}

#[tokio::test]
async fn test_multiple_listeners() {
    let notifier = Notifier::new();
    let (_id1, mut rx1) = notifier.register_listener(Scope::all());
    let (_id2, mut rx2) = notifier.register_listener(Scope::all());

    notifier.notify(Notification::SinkBlueScoreChanged(
        SinkBlueScoreChangedNotification {
            sink_blue_score: 42,
        },
    ));

    assert!(rx1.recv().await.is_some());
    assert!(rx2.recv().await.is_some());
}
