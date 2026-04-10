use misaka_notify::events::EventType;
use misaka_notify::notification::*;
use misaka_notify::notifier::Notifier;
use misaka_notify::scope::Scope;

#[tokio::test]
async fn test_notifier_basic() {
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
    assert!(matches!(msg.payload, NotificationPayload::BlockAdded(_)));
}

#[tokio::test]
async fn test_notifier_scoped_events() {
    // Notifier configured to only handle BlockAdded events
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let notifier = Notifier::with_events(tx, vec![EventType::BlockAdded]);

    // Send a BlockAdded notification (should arrive)
    let n1 = Notification {
        event_type: EventType::BlockAdded,
        payload: NotificationPayload::BlockAdded(BlockAddedNotification {
            block_hash: "01".repeat(32),
            blue_score: 1,
        }),
    };
    notifier.notify(n1).await.expect("notify");

    // Send a VirtualDaaScoreChanged notification (should be filtered out)
    let n2 = Notification {
        event_type: EventType::VirtualDaaScoreChanged,
        payload: NotificationPayload::VirtualDaaScoreChanged(
            VirtualDaaScoreChangedNotification {
                virtual_daa_score: 100,
            },
        ),
    };
    notifier.notify(n2).await.expect("filtered");

    let msg = rx.recv().await.expect("recv");
    assert_eq!(msg.event_type, EventType::BlockAdded);

    // Channel should be empty (DAA was filtered by the notifier)
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn test_notifier_try_notify() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let notifier = Notifier::new(tx);

    let notification = Notification {
        event_type: EventType::SinkBlueScoreChanged,
        payload: NotificationPayload::SinkBlueScoreChanged(
            SinkBlueScoreChangedNotification {
                sink_blue_score: 42,
            },
        ),
    };
    notifier.try_notify(notification).expect("try_notify");

    let msg = rx.recv().await.expect("recv");
    assert_eq!(msg.event_type, EventType::SinkBlueScoreChanged);
}

#[test]
fn test_scope_matches() {
    let scope_all = Scope::All;
    assert!(scope_all.matches(&EventType::BlockAdded));
    assert!(scope_all.matches(&EventType::UtxosChanged));

    let scope_single = Scope::Single(EventType::BlockAdded);
    assert!(scope_single.matches(&EventType::BlockAdded));
    assert!(!scope_single.matches(&EventType::UtxosChanged));
}
