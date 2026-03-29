//! Notifier: high-level interface for emitting notifications.

use crate::notification::Notification;
use crate::events::EventType;
use tokio::sync::mpsc;

/// High-level notifier for emitting events into the notification system.
pub struct Notifier {
    sender: mpsc::Sender<Notification>,
    enabled_events: Vec<EventType>,
}

impl Notifier {
    pub fn new(sender: mpsc::Sender<Notification>) -> Self {
        Self {
            sender,
            enabled_events: EventType::all().to_vec(),
        }
    }

    pub fn with_events(sender: mpsc::Sender<Notification>, events: Vec<EventType>) -> Self {
        Self { sender, enabled_events: events }
    }

    pub fn is_enabled(&self, event: &EventType) -> bool {
        self.enabled_events.contains(event)
    }

    pub async fn notify(&self, notification: Notification) -> Result<(), ()> {
        if self.is_enabled(&notification.event_type) {
            self.sender.send(notification).await.map_err(|_| ())
        } else {
            Ok(())
        }
    }

    pub fn try_notify(&self, notification: Notification) -> Result<(), ()> {
        if self.is_enabled(&notification.event_type) {
            self.sender.try_send(notification).map_err(|_| ())
        } else {
            Ok(())
        }
    }
}
