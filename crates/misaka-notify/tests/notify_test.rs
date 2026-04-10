use misaka_notify::events::EventType;
use misaka_notify::notification::*;
use misaka_notify::notifier::Notifier;
use misaka_notify::scope::Scope;

#[tokio::test]
async fn test_register_and_notify() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let notifier = Notifier::new(tx);

    let notification = Notification {
        event_type: EventType::BlockAdded,
        payload: NotificationPayload::BlockAdded(BlockAddedNotification {
            block_hash: "01".repeat(32),
            blue_score: 1,
        }),
    };
    notifier.notify(notification).await.expect("notify");

    let msg = rx.recv().await.expect("recv");
    assert_eq!(msg.event_type, EventType::BlockAdded);
}

#[tokio::test]
async fn test_scoped_subscription() {
    // Only enabled for UtxosChanged
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let notifier = Notifier::with_events(tx, vec![EventType::UtxosChanged]);

    // Send a BlockAdded — should NOT be received (filtered by notifier)
    let n1 = Notification {
        event_type: EventType::BlockAdded,
        payload: NotificationPayload::BlockAdded(BlockAddedNotification {
            block_hash: "01".repeat(32),
            blue_score: 1,
        }),
    };
    notifier.notify(n1).await.expect("filtered");

    // Send UtxosChanged — should be received
    let n2 = Notification {
        event_type: EventType::UtxosChanged,
        payload: NotificationPayload::UtxosChanged(UtxosChangedNotification {
            added: vec![],
            removed: vec![],
        }),
    };
    notifier.notify(n2).await.expect("notify");

    let msg = rx.recv().await.expect("recv");
    assert_eq!(msg.event_type, EventType::UtxosChanged);
}

#[tokio::test]
async fn test_unregister() {
    let (tx, _rx) = tokio::sync::mpsc::channel(16);
    let notifier = Notifier::new(tx);

    // Dropping the receiver — try_notify should return Err but not panic
    drop(_rx);
    let notification = Notification {
        event_type: EventType::BlockAdded,
        payload: NotificationPayload::BlockAdded(BlockAddedNotification {
            block_hash: "00".repeat(32),
            blue_score: 0,
        }),
    };
    let _ = notifier.try_notify(notification);
}

#[test]
fn test_event_types_all() {
    assert_eq!(EventType::all().len(), 10);
}

#[test]
fn test_scope_filtering() {
    let scope = Scope::Single(EventType::UtxosChanged);
    assert!(scope.matches(&EventType::UtxosChanged));
    assert!(!scope.matches(&EventType::BlockAdded));

    let scope_all = Scope::All;
    assert!(scope_all.matches(&EventType::BlockAdded));
    assert!(scope_all.matches(&EventType::UtxosChanged));
    assert!(scope_all.matches(&EventType::MempoolChanged));
}
